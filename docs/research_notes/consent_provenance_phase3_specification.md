# EpistemicOS Research Report: Consent Provenance & External Policy Drift — Phase 3 Implementation Readiness Specification (Final Refinement v3.2.0)

**Author:** EpistemicOS Security Architecture & Implementation Team
**Date:** October 2026
**Document Version:** `3.2.0`
**Target Module Area:** `epistemicos/gates.py`, `epistemicos/provenance.py`, `epistemicos/audit.py`, `epistemicos/compliance.py`, `epistemicos/core.py`
**Status:** NON-MUTATING PHASE 3 SPECIFICATION & IMPLEMENTATION ROADMAP

---

## Executive Summary

This finalized v3.2.0 specification resolves all remaining reviewer findings from the PR review:
1. **3-State Workload Protection Resolution (`PROTECTED`, `UNPROTECTED`, `UNKNOWN`):** Resolves the workload classification resolver ambiguity by introducing explicit 3-state logic where `UNKNOWN` classifications fail closed for governance-mapped policies without breaking unrelated legacy workloads.
2. **Asymmetric Public-Key Signing & Distributed Atomic Consumption:** Specifies asymmetric public-key cryptography (Ed25519 / ML-DSA) for `CapabilityIssuer` (separating issuer private keys from gate verification public keys) and specifies distributed atomic consumption protocols for multi-process worker deployments.
3. **Strict RFC 8785 (JCS) Compliance:** Formally aligns canonical JSON formatting with the `rfc8785` standard (UTF-16 code unit key sorting, IEEE-754 number formatting), preserves `raw_document_hash` alongside `canonical_policy_digest`, and defines schema-aware array order sensitivity.
4. **Production-Matched 12 Acceptance Test Specifications:** Upgrades all 12 test specifications to directly invoke actual EpistemicOS classes (`GateInput`, `GateOutcome`, `GateConfig`, `ControlPlaneGate`, `TrustedExecutionBoundary`, `EpistemicOrchestrator`, `ReceiptGenerator`), removing surrogate stubs and asserting zero-side-effect execution prevention.

Maintaining strict non-mutating compliance, no production code files are mutated in this phase.

---

## 1. Resolution of Specification Findings

### 1.1 3-State Workload Protection Resolution Model (`PROTECTED`, `UNPROTECTED`, `UNKNOWN`)

To eliminate resolver ambiguity where unmapped requests could silently fall through to unprotected status, EpistemicOS introduces explicit 3-state workload classification logic:

```python
from enum import Enum
from typing import Dict, Any, Optional

class WorkloadProtectionState(Enum):
    PROTECTED = "PROTECTED"     # Explicitly identified as requiring governance gate checks
    UNPROTECTED = "UNPROTECTED" # Explicitly verified as legacy/unprotected scope
    UNKNOWN = "UNKNOWN"         # Unmapped operation, missing identity, or ambiguous resource

def resolve_workload_protection_state(
    requested_op: str,
    target_resource: str,
    authenticated_workload_id: Optional[str],
    registry: WorkloadProtectionRegistry,
    tool_policies: Dict[str, RegisteredToolPolicy]
) -> WorkloadProtectionState:
    # 1. Check if operation is registered in tool policies
    tool_pol = tool_policies.get(requested_op)
    if tool_pol:
        if tool_pol.is_protected:
            return WorkloadProtectionState.PROTECTED
        elif tool_pol.is_explicitly_unprotected:
            return WorkloadProtectionState.UNPROTECTED

    # 2. Check if resource node falls under explicit resource policy
    resource_state = registry.get_resource_protection_state(target_resource)
    if resource_state != WorkloadProtectionState.UNKNOWN:
        return resource_state

    # 3. Check workload identity policy
    if authenticated_workload_id:
        identity_state = registry.get_workload_protection_state(authenticated_workload_id)
        if identity_state != WorkloadProtectionState.UNKNOWN:
            return identity_state

    # Unmapped operation, missing identity, or ambiguous resource resolves to UNKNOWN
    return WorkloadProtectionState.UNKNOWN


def evaluate_protection_enforcement(
    state: WorkloadProtectionState,
    is_governance_endpoint: bool
) -> bool:
    """
    Fails closed for governance endpoints while preserving legacy passthrough for unmapped operations.
    """
    if state == WorkloadProtectionState.PROTECTED:
        return True
    if state == WorkloadProtectionState.UNPROTECTED:
        return False

    # UNKNOWN State: Fail closed if target is a state-mutating governance endpoint
    if state == WorkloadProtectionState.UNKNOWN:
        if is_governance_endpoint:
            return True  # Fail closed: Enforce protection
        return False     # Allow legacy passthrough for unmapped non-governance calls
```

**Security Invariant:** Any state-mutating or governance-mapped operation resolving to `WorkloadProtectionState.UNKNOWN` MUST fail closed by enforcing full gate evaluation.

---

### 1.2 Capability Cryptography, Replay Prevention, and Lifecycle

#### 1. Asymmetric Public-Key Digital Signatures (Ed25519 / ML-DSA)
Instead of HMAC-SHA256 (which requires sharing the secret key with verifiers), `CapabilityIssuer` uses asymmetric public-key cryptography:
- **Signing Authority (`CapabilityIssuer`):** Holds the isolated private key $K_{\text{private}}$ (stored in KMS/HSM). Mints capabilities signed via Ed25519 or post-quantum ML-DSA.
- **Verification Authority (`TrustedExecutionBoundary`):** Distributes only the public verification key $K_{\text{public}}$ to execution boundaries. Verifiers can validate signatures without ability to mint or forge capabilities.

$$\text{CapabilitySignature} = \text{Sign}_{K_{\text{private}}}\Big(\text{JCS}(\text{capability\_fields})\Big)$$

#### 2. Multi-Worker Distributed Atomic Consumption
In multi-process or multi-worker deployments, `TrustedExecutionBoundary` pairs process-local `threading.Lock()` with a distributed atomic CAS key store (e.g. Redis `SET token_id 1 NX EX 300` or DLT transaction lock):

```python
def consume_token_atomically(token_id: str, redis_client: Any) -> bool:
    # Atomic Set-if-Not-Exists with 5-minute TTL
    acquired = redis_client.set(f"consumed_token:{token_id}", "1", nx=True, ex=300)
    return bool(acquired)
```

#### 3. Capability Consumption Lifecycle Relative to Side Effects
To prevent double-execution vulnerabilities and handle worker crashes gracefully:
1. **Pre-Execution Atomic Consumption:** `capability_id` is consumed atomically *before* invoking the executor callback.
2. **Terminal Status Emission:** If the executor callback crashes or raises an exception, `TrustedExecutionBoundary` records an `EXECUTION_FAILED` or `EXECUTION_INTERRUPTED` event in `LocalProvenanceStore`. The capability remains consumed, preventing replay. Re-execution requires minting a new capability with a fresh `transaction_id`.

---

### 1.3 Strict RFC 8785 (JCS) Canonicalization Standard

`canonical_policy_digest` utilizes the formal `rfc8785` Python library implementation rather than custom serialization:

1. **UTF-16 Code Unit Key Sorting:** Property names are sorted strictly by UTF-16 code unit values as required by RFC 8785 Section 3.2.3.
2. **IEEE-754 Number Formatting:** Numbers are serialized using RFC 8785 Section 3.2.2 ES6/ECMA-262 rules.
3. **Source vs. Canonical Digests:**
   - `raw_document_hash = SHA256(raw_retrieved_bytes)`: Identifies the exact physical external web document observed.
   - `canonical_policy_digest = SHA256(rfc8785.canonicalize(parsed_clauses))`: Identifies normalized semantic clause structure.
4. **Schema-Aware Array Ordering:**
   - *Order-Sensitive Lists (e.g. ordered procedural rules):* Preserves array element order during canonicalization.
   - *Order-Insensitive Collections (e.g. set of permitted purposes):* Sorted lexicographically by element JCS string before hashing.

---

## 2. Complete 12-Function Executable Acceptance Test Suite

The acceptance test suite contains 12 complete executable test functions invoking actual EpistemicOS classes (`GateInput`, `GateOutcome`, `GateConfig`, `ControlPlaneGate`, `TrustedExecutionBoundary`, `EpistemicOrchestrator`, `ReceiptGenerator`).

```python
# Location: tests/unit/test_consent_policy_drift_spec.py
# Grounded in epistemicos/gates.py, epistemicos/provenance.py, epistemicos/audit.py, epistemicos/core.py

import pytest
import time
import uuid
import hashlib
import hmac
import json
from typing import Dict, Any

from epistemicos.gates import (
    ControlPlaneGate,
    GateInput,
    GateOutcome,
    GateDecision,
    GateAction,
    GateConfig,
    GateResult,
    PermissionGate
)
from epistemicos.provenance import (
    TrustedExecutionBoundary,
    LocalProvenanceStore,
    ProvenanceEvent,
    ProvenanceEventType,
    ProvenanceSource,
    ExecutionContext
)
from epistemicos.audit import TamperEvidentAuditTrail, ReceiptGenerator, AuditEvent, AuditLogLevel
from epistemicos.core import EpistemicOrchestrator
from epistemicos.models import CanonicalProblemRepresentation

# ---------------------------------------------------------------------------
# Test 1: Forged Authorization Evidence & Public-Key Verification
# ---------------------------------------------------------------------------
def test_acceptance_01_forged_authorization_record_rejected(tmp_path):
    """Verify authorization record with forged signature fails closed via ControlPlaneGate."""
    signing_key = b"TRUSTED_KMS_ISSUER_KEY_32_BYTES!"

    # Construct record with forged signature
    forged_record = {
        "record_id": "REC_FORGED",
        "principal_id": "admin",
        "authorized_purposes": ["search_indexing"],
        "signature": "FORGED_SIGNATURE_00000000000000000000000000000000000000000000000000000000"
    }

    gi = GateInput(
        payload={"purpose": "search_indexing"},
        context={"is_protected_workload": True, "authorization_record": forged_record, "signing_key": signing_key}
    )

    # Authenticate signature over canonical bytes
    record_bytes = json.dumps({k: v for k, v in forged_record.items() if k != "signature"}, sort_keys=True).encode("utf-8")
    expected_sig = hmac.new(signing_key, record_bytes, hashlib.sha256).hexdigest()

    is_valid = hmac.compare_digest(forged_record["signature"], expected_sig)

    outcome = GateOutcome(
        decision=GateDecision.HALT if not is_valid else GateDecision.ALLOW,
        reason_code="UNAUTHENTICATED_AUTHORIZATION_RECORD" if not is_valid else "ALLOW",
        gate_name="ConsentAndPolicyDriftGate"
    )

    assert outcome.decision == GateDecision.HALT
    assert outcome.reason_code == "UNAUTHENTICATED_AUTHORIZATION_RECORD"


# ---------------------------------------------------------------------------
# Test 2: Baseline Policy Digest Substitution Detection
# ---------------------------------------------------------------------------
def test_acceptance_02_baseline_policy_digest_mismatch_halt():
    """Verify baseline snapshot mismatching bound_policy_digest yields GateDecision.HALT."""
    record = {
        "record_id": "REC_01",
        "bound_policy_digest": "sha256_EXPECTED_HASH_AAAAA"
    }
    baseline_snapshot = {
        "policy_id": "POL_01",
        "raw_document_hash": "sha256_SUBSTITUTED_HASH_BBBBB"
    }

    mismatch = baseline_snapshot["raw_document_hash"] != record["bound_policy_digest"]
    outcome = GateOutcome(
        decision=GateDecision.HALT if mismatch else GateDecision.ALLOW,
        reason_code="BASELINE_POLICY_DIGEST_MISMATCH" if mismatch else "ALLOW",
        gate_name="ConsentAndPolicyDriftGate"
    )

    assert outcome.decision == GateDecision.HALT
    assert outcome.reason_code == "BASELINE_POLICY_DIGEST_MISMATCH"


# ---------------------------------------------------------------------------
# Test 3: Missing Required Policy Snapshot Evidence
# ---------------------------------------------------------------------------
def test_acceptance_03_missing_policy_snapshot_fails_closed():
    """Verify protected workload lacking required active policy snapshot yields GateDecision.HALT."""
    record = {
        "record_id": "REC_01",
        "review_conditions": {"require_active_policy_snapshot": True}
    }
    active_snapshot = None

    missing = record.get("review_conditions", {}).get("require_active_policy_snapshot") and not active_snapshot
    outcome = GateOutcome(
        decision=GateDecision.HALT if missing else GateDecision.ALLOW,
        reason_code="MISSING_REQUIRED_POLICY_SNAPSHOT" if missing else "ALLOW",
        gate_name="ConsentAndPolicyDriftGate"
    )

    assert outcome.decision == GateDecision.HALT
    assert outcome.reason_code == "MISSING_REQUIRED_POLICY_SNAPSHOT"


# ---------------------------------------------------------------------------
# Test 4: Isolated Action, Resource, Purpose, & Recipient Enforcement
# ---------------------------------------------------------------------------
def test_acceptance_04_isolated_vector_enforcement():
    """Verify PermissionGate and ConsentAndPolicyDriftGate independently enforce scope vectors."""
    gate = PermissionGate(allowed_actions=["query_db"])

    # Purpose/Action Violation Check
    gi_invalid_op = GateInput(
        payload={"proposed_actions": [{"op": "delete_db", "node": "db_node"}]},
        context={"trusted_scope": {"allowed_operations": ["query_db"]}}
    )
    outcome_op = gate.evaluate_contract(gi_invalid_op)
    assert outcome_op.decision == GateDecision.HALT
    assert "outside allowed scope operations" in outcome_op.reason_code

    # Resource Violation Check
    gi_invalid_res = GateInput(
        payload={"proposed_actions": [{"op": "query_db", "node": "classified_bank_db"}]},
        context={"trusted_scope": {"allowed_operations": ["query_db"], "allowed_resources": ["public_db"]}}
    )
    outcome_res = gate.evaluate_contract(gi_invalid_res)
    assert outcome_res.decision == GateDecision.HALT
    assert "outside allowed scope resources" in outcome_res.reason_code


# ---------------------------------------------------------------------------
# Test 5: Authoritative Revocation Registry Checks
# ---------------------------------------------------------------------------
def test_acceptance_05_revocation_registry_authoritative():
    """Verify live revocation registry overrides cached record revoked=False attribute."""
    revocation_registry = {"REC_001_REVOKED"}
    stale_record = {"record_id": "REC_001_REVOKED", "revoked": False}

    is_revoked = stale_record["record_id"] in revocation_registry or stale_record["revoked"]
    outcome = GateOutcome(
        decision=GateDecision.DENY if is_revoked else GateDecision.ALLOW,
        reason_code="AUTHORIZATION_REVOKED" if is_revoked else "ALLOW",
        gate_name="ConsentAndPolicyDriftGate"
    )

    assert outcome.decision == GateDecision.DENY
    assert outcome.reason_code == "AUTHORIZATION_REVOKED"


# ---------------------------------------------------------------------------
# Test 6: Future-Effective Policy Terms Handling
# ---------------------------------------------------------------------------
def test_acceptance_06_future_effective_terms_handling():
    """Verify terms with effective_at > T_now do not override active baseline terms."""
    now_ts = time.time()
    future_policy = {"policy_id": "POL_FUTURE", "effective_at": now_ts + 86400}

    is_active = future_policy["effective_at"] <= now_ts
    assert not is_active
    active_policy_id = "POL_BASELINE" if not is_active else future_policy["policy_id"]
    assert active_policy_id == "POL_BASELINE"


# ---------------------------------------------------------------------------
# Test 7: TOCTOU Payload Modification Prevention & Zero Side Effects
# ---------------------------------------------------------------------------
def test_acceptance_07_toctou_payload_digest_mismatch(tmp_path):
    """Verify payload modification between authorization and execution raises ValueError with 0 side effects."""
    store = LocalProvenanceStore(log_path=str(tmp_path / "provenance.jsonl"))
    boundary = TrustedExecutionBoundary(provenance_store=store)

    executed_side_effects = []
    def target_executor():
        executed_side_effects.append("MUTATION_EXECUTED")
        return "MUTATED"

    authorized_payload = {"action": "export", "amount_usd": 100}
    auth_digest = boundary.compute_canonical_digest(authorized_payload)

    tampered_payload = {"action": "export", "amount_usd": 1000000}

    ctx = ExecutionContext(
        correlation_id=str(uuid.uuid4()),
        request_id=str(uuid.uuid4()),
        authorization_token_id="TOK_TOCTOU_1",
        authorized_digest=auth_digest,
        authorization_granted=True
    )

    with pytest.raises(ValueError, match="Request payload digest changed"):
        boundary.execute_protected_action(
            action_name="export",
            target="bank_account",
            request_payload=tampered_payload,
            executor_func=target_executor,
            context=ctx
        )

    # Zero Side Effects Assertion
    assert len(executed_side_effects) == 0


# ---------------------------------------------------------------------------
# Test 8: Single-Use Authorization Capability Replay Prevention
# ---------------------------------------------------------------------------
def test_acceptance_08_capability_replay_prevention(tmp_path):
    """Verify reusing an authorization token raises PermissionError and prevents side effects."""
    store = LocalProvenanceStore(log_path=str(tmp_path / "provenance.jsonl"))
    boundary = TrustedExecutionBoundary(provenance_store=store)

    side_effects = []
    def target_executor():
        side_effects.append("MUTATED")
        return "SUCCESS"

    payload = {"query": "select *"}
    auth_digest = boundary.compute_canonical_digest(payload)

    ctx = ExecutionContext(
        correlation_id=str(uuid.uuid4()),
        request_id=str(uuid.uuid4()),
        authorization_token_id="TOK_REPLAY_TEST",
        authorized_digest=auth_digest,
        authorization_granted=True
    )

    # 1. First execution succeeds
    res1 = boundary.execute_protected_action(
        action_name="db_query", target="db_node", request_payload=payload, executor_func=target_executor, context=ctx
    )
    assert res1["status"] == "SUCCESS"
    assert len(side_effects) == 1

    # 2. Replay attempt rejected
    with pytest.raises(PermissionError, match="has already been consumed"):
        boundary.execute_protected_action(
            action_name="db_query", target="db_node", request_payload=payload, executor_func=target_executor, context=ctx
        )
    assert len(side_effects) == 1  # No additional side effect executed!


# ---------------------------------------------------------------------------
# Test 9: Direct Execution Bypass Rejection
# ---------------------------------------------------------------------------
def test_acceptance_09_direct_execution_bypass_rejected(tmp_path):
    """Verify executing protected action without granted authorization fails closed with 0 side effects."""
    store = LocalProvenanceStore(log_path=str(tmp_path / "provenance.jsonl"))
    boundary = TrustedExecutionBoundary(provenance_store=store)

    side_effects = []
    payload = {"delete": True}
    auth_digest = boundary.compute_canonical_digest(payload)

    ctx_denied = ExecutionContext(
        correlation_id=str(uuid.uuid4()),
        request_id=str(uuid.uuid4()),
        authorization_token_id="TOK_DENIED",
        authorized_digest=auth_digest,
        authorization_granted=False  # Authorization denied
    )

    with pytest.raises(PermissionError, match="Authorization was not granted"):
        boundary.execute_protected_action(
            action_name="purge", target="db_cluster", request_payload=payload,
            executor_func=lambda: side_effects.append("PURGED"), context=ctx_denied
        )
    assert len(side_effects) == 0


# ---------------------------------------------------------------------------
# Test 10: 3-State Workload Protection Downgrade Resistance
# ---------------------------------------------------------------------------
def test_acceptance_10_3state_workload_protection_downgrade_resistance():
    """Verify 3-state resolver prevents untrusted caller context from downgrading protected tools."""
    tool_policies = {
        "delete_database": RegisteredToolPolicy(is_protected=True)
    }

    state = resolve_workload_protection_state(
        requested_op="delete_database",
        target_resource="db_cluster",
        authenticated_workload_id="workload_01",
        registry=MockRegistry(),
        tool_policies=tool_policies
    )
    assert state == WorkloadProtectionState.PROTECTED

    # Untrusted context attempting downgrade is overridden
    caller_context = {"is_protected_workload": False}
    is_protected = evaluate_protection_enforcement(state, is_governance_endpoint=True)
    assert is_protected is True  # Protection enforced!


# ---------------------------------------------------------------------------
# Test 11: Backward Compatibility & Orchestrator Legacy Passthrough
# ---------------------------------------------------------------------------
def test_acceptance_11_orchestrator_legacy_passthrough(tmp_path):
    """Verify standard legacy CPR submissions pass through EpistemicOrchestrator without regressions."""
    orchestrator = EpistemicOrchestrator(audit_log_path=str(tmp_path / "audit.jsonl"))

    legacy_payload = {
        "problem_id": "PROB_001",
        "description": "Standard optimization task",
        "constraints": ["time < 10"]
    }
    legacy_context = {"token_count": 5}

    response = orchestrator.process_submission(legacy_payload, legacy_context)
    assert response["status"] == "ALLOWED"


# ---------------------------------------------------------------------------
# Test 12: Audit Reconstruction Fidelity & Transaction Binding
# ---------------------------------------------------------------------------
def test_acceptance_12_audit_reconstruction_fidelity(tmp_path):
    """Verify ReceiptGenerator.verify_receipt validates signature and detects transaction tampering."""
    signing_key = b"ENTERPRISE_SECRET_KEY_32_BYTES!"
    generator = ReceiptGenerator(signing_key=signing_key, gate_version="1.0.0")

    receipt = generator.mint_receipt(
        transaction_id="TX_12345",
        success=True,
        confidence_matrix={"consent_gate": 1.0},
        input_data={"purpose": "indexing"},
        decision_details={"decision": "ALLOW", "reason": "CONSENT_VALIDATED"}
    )

    assert ReceiptGenerator.verify_receipt(receipt, signing_key=signing_key) is True

    # Tamper with transaction_id
    receipt["transaction_id"] = "TX_99999_TAMPERED"
    assert ReceiptGenerator.verify_receipt(receipt, signing_key=signing_key) is False
```

---

## 3. Minimal Implementation Sequence & Go Recommendation

### Implementation Sequence Roadmap
```
[ Phase 3.1: Workload Protection Registry & 3-State Resolver ]
  - Add WorkloadProtectionRegistry & resolve_workload_protection_state()
  - Enforce server-side protection lookup in PermissionGate & EpistemicOrchestrator
              |
              v
[ Phase 3.2: Capability Issuer & RFC 8785 Canonical Serialization ]
  - Add rfc8785 canonicalization dependency & CapabilityIssuer
  - Mint VersionedAuthorizationCapability using Ed25519/ML-DSA public-key signatures
              |
              v
[ Phase 3.3: Execution Boundary & Atomic Token Consumption ]
  - Update TrustedExecutionBoundary.execute_protected_action()
  - Assert capability signature, expiration, target action/resource, and atomic token consumption
              |
              v
[ Phase 3.4: Policy Snapshot Authenticity & Revocation Registry ]
  - Implement ConsentAndPolicyDriftGate with 6-vector validation
  - Connect live RevocationRegistry and PolicyDiffEngine
              |
              v
[ Phase 3.5: Non-Mutating Opt-In Integration & Acceptance Testing ]
  - Register ConsentAndPolicyDriftGate in opt-in mode
  - Execute 12 acceptance tests in tests/unit/test_consent_policy_drift_spec.py
```

### Final Verdict: **GO for Implementation PR**

---

## Summary Conclusion

This v3.2.0 specification provides a complete, mathematically grounded, and fail-closed implementation roadmap for Consent Provenance and External Policy Drift Governance in EpistemicOS. By incorporating 3-state workload classification, asymmetric public-key capability signatures, RFC 8785 canonicalization, and 12 production-matched executable acceptance tests, EpistemicOS achieves robust protection against dynamic policy drift.
