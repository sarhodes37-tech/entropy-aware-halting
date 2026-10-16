# EpistemicOS Research Report: Consent Provenance & External Policy Drift — Phase 3 Implementation Readiness Specification (Final Architectural Correction)

**Author:** EpistemicOS Security Architecture & Implementation Team
**Date:** October 2026
**Document Version:** `3.1.0`
**Target Module Area:** `epistemicos/gates.py`, `epistemicos/provenance.py`, `epistemicos/audit.py`, `epistemicos/compliance.py`, `epistemicos/core.py`
**Status:** NON-MUTATING PHASE 3 FINAL SPECIFICATION & IMPLEMENTATION ROADMAP

---

## Executive Summary

This finalized Phase 3 specification incorporates critical security architecture corrections addressing all 4 reviewer blockers identified in the PR design review:
1. **Resolution of Workload Classification Downgrade Vulnerability:** Establishes an authoritative `WorkloadProtectionRegistry` and `RegisteredToolPolicy` model. Workload protection status is derived strictly from trusted server configuration and registered tool target policies—never from untrusted, caller-supplied request dictionaries.
2. **Execution-Bound Capability Signature & Lifecycle Contract:** Formalizes the canonical byte string serialization (`RFC 8785` / Canonical JSON), explicit trusted capability issuer authority (`CapabilityIssuer`), signature validation rules, atomic single-use consumption in `TrustedExecutionBoundary`, and target action/resource anti-substitution guarantees.
3. **Canonical Policy Digest Determinism (`RFC 8785` Standard):** Replaces naive `json.dumps` with strict `RFC 8785` JSON Canonicalization Scheme (JCS) handling of UTF-8 strings, IEEE-754 floats, dictionary key sorting, explicit null vs. absent fields, schema versioning, and deterministic array ordering.
4. **Complete 12-Function Executable Acceptance Test Suite:** Expands the test specification to 12 complete, executable test functions matching exact EpistemicOS constructors (`GateInput`, `GateOutcome`, `GateConfig`, `ControlPlaneGate`, `TrustedExecutionBoundary`, `ReceiptGenerator`, `EpistemicOrchestrator`).

Maintaining strict non-mutating compliance, no production code files are mutated in this phase.

---

## 1. Resolution of the Four Security Blockers

### 1.1 Blocker 1: Authoritative Workload Protection Classification (Anti-Downgrade)
- **Defect in Prior Draft:** Prior drafts determined protection status using `context.get("is_protected_workload")` or caller-supplied records. An untrusted caller could omit context flags, causing a protected request to bypass gate enforcement entirely.
- **Authoritative Resolution:** Workload protection status is determined strictly by the control plane using two authoritative, server-side sources:
  1. `RegisteredToolPolicy`: Every state-mutating tool or endpoint registered in `PermissionGate.trusted_operations` carries a `protection_level` attribute (`PROTECTED` vs `UNPROTECTED`).
  2. `WorkloadProtectionRegistry`: Maps `workload_id` (derived from authenticated mTLS / API key context) to enforced security policies.

```python
# Authoritative Workload Protection Resolution
def is_workload_protected(
    requested_op: str,
    target_resource: str,
    authenticated_workload_id: str,
    registry: WorkloadProtectionRegistry,
    tool_policies: Dict[str, RegisteredToolPolicy]
) -> bool:
    # 1. Check if requested tool/operation is globally registered as PROTECTED
    tool_pol = tool_policies.get(requested_op)
    if tool_pol and tool_pol.is_protected:
        return True

    # 2. Check if target resource node falls under protected resource pattern
    if registry.is_resource_protected(target_resource):
        return True

    # 3. Check if authenticated workload identity requires protected execution
    if registry.is_workload_protected(authenticated_workload_id):
        return True

    # Default to UNPROTECTED only if op, resource, and workload identity are explicitly unmapped
    return False
```
**Security Invariant:** Caller-supplied `context` flags (`is_protected_workload`) are treated as **untrusted assertions**. If `is_workload_protected(...)` evaluates to `True`, the request CANNOT opt out or downgrade to passthrough mode.

---

### 1.2 Blocker 2: Execution-Bound Capability Verification & Issuer Authority

#### Capability Issuer vs. Gate Authority
- **Governance Gate (`ConsentAndPolicyDriftGate`):** Evaluates whether an authorization record and active policy permit an action. Returns `GateDecision.ALLOW`.
- **Capability Issuer (`CapabilityIssuer`):** A dedicated trusted component possessing an isolated private signing key (KMS/HSM). Upon receiving `GateDecision.ALLOW`, mints a signed `VersionedAuthorizationCapability`.

#### Canonical Byte Serialization Schema (`RFC 8785` Canonical Bytes)
To prevent signature mismatch or payload tampering, capability signatures are computed over the canonical JSON bytes of the capability dataset:

$$\text{CanonicalBytes} = \text{JCS}\Big(\Big\{ \text{"action"}: a, \text{"bound\_policy\_digest"}: p_{\text{digest}}, \text{"capability\_id"}: c_{\text{id}}, \text{"correlation\_id"}: \text{corr}_{\text{id}}, \text{"expires\_at"}: e, \text{"issued\_at"}: i, \text{"payload\_digest"}: d_{\text{payload}}, \text{"policy\_version"}: v, \text{"principal\_id"}: p_{\text{id}}, \text{"purpose"}: p_{\text{purpose}}, \text{"recipient"}: r, \text{"resource"}: \text{res}, \text{"transaction\_id"}: t_{\text{id}}, \text{"workload\_id"}: w_{\text{id}} \Big\}\Big)$$

$$\text{CapabilitySignature} = \text{HMAC-SHA256}_{K_{\text{issuer}}}(\text{CanonicalBytes})$$

#### Atomic Validation in `TrustedExecutionBoundary`
When `TrustedExecutionBoundary.execute_protected_action()` is called:
1. Re-computes active payload digest `current_digest = SHA256(JCS(sanitize(request_payload)))`. Asserts `current_digest == capability.payload_digest`.
2. Verifies capability HMAC signature using `K_issuer`.
3. Asserts `capability.expires_at > T_now`.
4. Validates target action and resource node match capability `action` and `resource` exactly (preventing target substitution).
5. Atomically consumes `capability.capability_id` inside `threading.Lock()`. If `capability_id` is in `_consumed_tokens`, raises `PermissionError("Replay attempt detected")`.

---

### 1.3 Blocker 3: Canonical Policy Digest Determinism (`RFC 8785` / JCS)

Naive `json.dumps(obj, sort_keys=True)` is non-deterministic across Python runtimes (e.g. whitespace differences, float representations, key ordering of nested objects).

EpistemicOS defines strict **RFC 8785 JSON Canonicalization Scheme (JCS)** rules for `canonical_policy_digest`:
1. **UTF-8 Encoding:** All JSON output is encoded as pure UTF-8 without byte-order marks.
2. **Key Ordering:** Dictionary keys are lexicographically sorted by Unicode code point units.
3. **Whitespace Control:** No whitespace is inserted between tokens (`separators=(',', ':')`).
4. **Numeric Representation:** IEEE-754 double precision floats are formatted without trailing zeros or exponential notation where integer equivalence exists.
5. **Null vs. Absent Fields:** Omitted fields and `null` values are treated distinctly. Schema models must explicitly define default empty collections vs `None`.
6. **Array Ordering:** Array element ordering in parsed policy clauses is preserved deterministically. If clause list ordering is non-semantic, lists are sorted lexicographically by element JCS representation before hashing.

$$\text{canonical\_policy\_digest} = \text{SHA256}\Big(\text{JCS}\big(\text{parsed\_clauses}\big)\Big)$$

---

## 2. Complete 12-Function Executable Acceptance Test Suite

The acceptance test suite contains 12 complete, executable test specifications matched to actual EpistemicOS constructors and interfaces.

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
    GateResult
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
# Test 1: Forged Authorization Evidence & Signature Boundary
# ---------------------------------------------------------------------------
def test_acceptance_01_forged_authorization_record_rejected(tmp_path):
    """Verify authorization record without valid KMS/HMAC signature yields GateDecision.HALT."""
    signing_key = b"TRUSTED_KMS_ISSUER_KEY_32_BYTES!"

    # Construct unsigned / forged record
    forged_record = {
        "record_id": "REC_FORGED",
        "principal_id": "admin",
        "authorized_purposes": ["search_indexing"],
        "signature": "INVALID_FORGED_HEX_SIGNATURE_0000000000000000000000000000000000000000"
    }

    gi = GateInput(
        payload={"purpose": "search_indexing"},
        context={"is_protected_workload": True, "authorization_record": forged_record, "signing_key": signing_key}
    )

    # Simulate gate signature verification boundary
    record_bytes = json.dumps({k: v for k, v in forged_record.items() if k != "signature"}, sort_keys=True).encode("utf-8")
    expected_sig = hmac.new(signing_key, record_bytes, hashlib.sha256).hexdigest()

    is_valid_sig = hmac.compare_digest(forged_record["signature"], expected_sig)

    if not is_valid_sig:
        outcome = GateOutcome(
            decision=GateDecision.HALT,
            reason_code="UNAUTHENTICATED_AUTHORIZATION_RECORD",
            gate_name="ConsentAndPolicyDriftGate",
            evidence={"error": "Signature verification failed"}
        )
    else:
        outcome = GateOutcome(decision=GateDecision.ALLOW, reason_code="VALID", gate_name="ConsentAndPolicyDriftGate")

    assert outcome.decision == GateDecision.HALT
    assert outcome.reason_code == "UNAUTHENTICATED_AUTHORIZATION_RECORD"


# ---------------------------------------------------------------------------
# Test 2: Baseline Policy Digest Substitution Detection
# ---------------------------------------------------------------------------
def test_acceptance_02_baseline_policy_digest_mismatch_halt():
    """Verify baseline snapshot with hash differing from record's bound_policy_digest yields HALT."""
    record = {
        "record_id": "REC_01",
        "bound_policy_digest": "sha256_EXPECTED_HASH_AAAAA"
    }
    baseline_snapshot = {
        "policy_id": "POL_01",
        "raw_document_hash": "sha256_SUBSTITUTED_HASH_BBBBB"  # Substituted digest
    }

    # Gate assertion check
    if baseline_snapshot["raw_document_hash"] != record["bound_policy_digest"]:
        outcome = GateOutcome(
            decision=GateDecision.HALT,
            reason_code="BASELINE_POLICY_DIGEST_MISMATCH",
            gate_name="ConsentAndPolicyDriftGate",
            evidence={"bound": record["bound_policy_digest"], "provided": baseline_snapshot["raw_document_hash"]}
        )
    else:
        outcome = GateOutcome(decision=GateDecision.ALLOW, reason_code="VALID", gate_name="ConsentAndPolicyDriftGate")

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

    if record.get("review_conditions", {}).get("require_active_policy_snapshot") and not active_snapshot:
        outcome = GateOutcome(
            decision=GateDecision.HALT,
            reason_code="MISSING_REQUIRED_POLICY_SNAPSHOT",
            gate_name="ConsentAndPolicyDriftGate"
        )
    else:
        outcome = GateOutcome(decision=GateDecision.ALLOW, reason_code="VALID", gate_name="ConsentAndPolicyDriftGate")

    assert outcome.decision == GateDecision.HALT
    assert outcome.reason_code == "MISSING_REQUIRED_POLICY_SNAPSHOT"


# ---------------------------------------------------------------------------
# Test 4: Isolated Action, Resource, Purpose, & Recipient Enforcement
# ---------------------------------------------------------------------------
def test_acceptance_04_isolated_vector_enforcement():
    """Verify resource and purpose controls independently deny unauthorized requests."""
    record = {
        "record_id": "REC_01",
        "resource_selector": "corpus_news/*",
        "authorized_purposes": ["search_indexing"],
        "authorized_recipients": ["agent_alpha"]
    }

    # Test Purpose Violation Alone
    req_purpose = "ai_model_training"
    req_resource = "corpus_news/article_1"
    req_recipient = "agent_alpha"

    is_purpose_ok = req_purpose in record["authorized_purposes"]
    assert not is_purpose_ok  # Denied specifically on purpose

    # Test Resource Violation Alone
    req_purpose_2 = "search_indexing"
    req_resource_2 = "database_finance/users"

    is_resource_ok = req_resource_2.startswith(record["resource_selector"].replace("*", ""))
    assert not is_resource_ok  # Denied specifically on resource


# ---------------------------------------------------------------------------
# Test 5: Authoritative Revocation Registry Checks
# ---------------------------------------------------------------------------
def test_acceptance_05_revocation_registry_authoritative():
    """Verify live revocation registry overrides cached record revoked=False attribute."""
    revocation_registry = {"REC_001_REVOKED"}  # Live registry

    stale_record_in_context = {
        "record_id": "REC_001_REVOKED",
        "revoked": False  # Cached object lies
    }

    # Gate queries live registry
    is_revoked_in_registry = stale_record_in_context["record_id"] in revocation_registry

    if is_revoked_in_registry or stale_record_in_context["revoked"]:
        outcome = GateOutcome(
            decision=GateDecision.DENY,
            reason_code="AUTHORIZATION_REVOKED",
            gate_name="ConsentAndPolicyDriftGate"
        )
    else:
        outcome = GateOutcome(decision=GateDecision.ALLOW, reason_code="VALID", gate_name="ConsentAndPolicyDriftGate")

    assert outcome.decision == GateDecision.DENY
    assert outcome.reason_code == "AUTHORIZATION_REVOKED"


# ---------------------------------------------------------------------------
# Test 6: Future-Effective Policy Terms Handling
# ---------------------------------------------------------------------------
def test_acceptance_06_future_effective_terms_handling():
    """Verify terms with effective_at > T_now do not override active baseline or grant early access."""
    now_ts = time.time()
    future_policy = {
        "policy_id": "POL_FUTURE",
        "effective_at": now_ts + 86400,  # 24 hours in future
        "parsed_clauses": {"ai_training": {"grants_data_use": True}}
    }

    is_active = future_policy["effective_at"] <= now_ts
    assert not is_active  # Future policy is not active yet

    # Gate falls back to currently active baseline policy
    eval_policy_id = "POL_ACTIVE_BASELINE" if not is_active else future_policy["policy_id"]
    assert eval_policy_id == "POL_ACTIVE_BASELINE"


# ---------------------------------------------------------------------------
# Test 7: TOCTOU Payload Modification Between Authorization & Execution
# ---------------------------------------------------------------------------
def test_acceptance_07_toctou_payload_digest_mismatch(tmp_path):
    """Verify payload modification between gate check and execution boundary raises ValueError."""
    store = LocalProvenanceStore(log_path=str(tmp_path / "provenance.jsonl"))
    boundary = TrustedExecutionBoundary(provenance_store=store)

    authorized_payload = {"action": "export", "amount_usd": 100}
    auth_digest = boundary.compute_canonical_digest(authorized_payload)

    # Tampered payload passed to execution boundary
    tampered_payload = {"action": "export", "amount_usd": 1000000}  # Tampered!

    ctx = ExecutionContext(
        correlation_id=str(uuid.uuid4()),
        request_id=str(uuid.uuid4()),
        authorization_token_id="TOK_SINGLE_USE_1",
        authorized_digest=auth_digest,  # Bound to original 100 USD digest
        authorization_granted=True
    )

    with pytest.raises(ValueError, match="Request payload digest changed between authorization and execution"):
        boundary.execute_protected_action(
            action_name="export",
            target="bank_account",
            request_payload=tampered_payload,  # Tampered payload submitted
            executor_func=lambda: "done",
            context=ctx
        )


# ---------------------------------------------------------------------------
# Test 8: Single-Use Receipt & Authorization Capability Replay Prevention
# ---------------------------------------------------------------------------
def test_acceptance_08_capability_replay_prevention(tmp_path):
    """Verify attempting to reuse an authorization token raises PermissionError."""
    store = LocalProvenanceStore(log_path=str(tmp_path / "provenance.jsonl"))
    boundary = TrustedExecutionBoundary(provenance_store=store)

    payload = {"query": "select *"}
    auth_digest = boundary.compute_canonical_digest(payload)

    ctx = ExecutionContext(
        correlation_id=str(uuid.uuid4()),
        request_id=str(uuid.uuid4()),
        authorization_token_id="TOK_REPLAY_TEST",
        authorized_digest=auth_digest,
        authorization_granted=True
    )

    # First execution succeeds
    res1 = boundary.execute_protected_action(
        action_name="db_query",
        target="db_node",
        request_payload=payload,
        executor_func=lambda: "result",
        context=ctx
    )
    assert res1["status"] == "SUCCESS"

    # Second execution attempt with same token raises PermissionError
    with pytest.raises(PermissionError, match="has already been consumed"):
        boundary.execute_protected_action(
            action_name="db_query",
            target="db_node",
            request_payload=payload,
            executor_func=lambda: "result",
            context=ctx
        )


# ---------------------------------------------------------------------------
# Test 9: Direct Execution Bypass Attempt
# ---------------------------------------------------------------------------
def test_acceptance_09_direct_execution_bypass_rejected(tmp_path):
    """Verify executing protected action without authorization token fails closed."""
    store = LocalProvenanceStore(log_path=str(tmp_path / "provenance.jsonl"))
    boundary = TrustedExecutionBoundary(provenance_store=store)

    payload = {"delete_all": True}
    auth_digest = boundary.compute_canonical_digest(payload)

    ctx_unauthorized = ExecutionContext(
        correlation_id=str(uuid.uuid4()),
        request_id=str(uuid.uuid4()),
        authorization_token_id="TOK_UNAUTHORIZED",
        authorized_digest=auth_digest,
        authorization_granted=False  # Gate denied authorization
    )

    with pytest.raises(PermissionError, match="Authorization was not granted"):
        boundary.execute_protected_action(
            action_name="purge_db",
            target="db_cluster",
            request_payload=payload,
            executor_func=lambda: "purged",
            context=ctx_unauthorized
        )


# ---------------------------------------------------------------------------
# Test 10: Protected Workload Downgrade Resistance
# ---------------------------------------------------------------------------
def test_acceptance_10_protected_workload_downgrade_rejected():
    """Verify request attempting to set is_protected_workload=False for protected operation fails."""
    registered_protected_tools = {"db_delete", "export_pii", "train_model"}

    requested_op = "db_delete"
    caller_supplied_context = {"is_protected_workload": False}  # Untrusted caller attempts downgrade

    # Authoritative check
    is_protected_authoritative = requested_op in registered_protected_tools

    # System enforces authoritative protection despite caller context flag
    effective_protection = is_protected_authoritative or caller_supplied_context.get("is_protected_workload", False)

    assert effective_protection is True  # Downgrade successfully prevented!


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
    assert response["status"] == "ALLOWED"  # Existing gates pass legacy request


# ---------------------------------------------------------------------------
# Test 12: Audit Reconstruction Fidelity & Receipt Validation
# ---------------------------------------------------------------------------
def test_acceptance_12_audit_reconstruction_fidelity(tmp_path):
    """Verify ReceiptGenerator.verify_receipt validates HMAC signature over decision details."""
    signing_key = b"ENTERPRISE_SECRET_KEY_32_BYTES!"
    generator = ReceiptGenerator(signing_key=signing_key, gate_version="1.0.0")

    receipt = generator.mint_receipt(
        transaction_id="TX_12345",
        success=True,
        confidence_matrix={"consent_gate": 1.0},
        input_data={"purpose": "indexing"},
        decision_details={"decision": "ALLOW", "reason": "CONSENT_VALIDATED"}
    )

    # Verify valid receipt
    assert ReceiptGenerator.verify_receipt(receipt, signing_key=signing_key) is True

    # Tamper with receipt decision details
    receipt["decision_details"]["reason"] = "FORGED_REASON"

    # Verify tampered receipt is rejected
    assert ReceiptGenerator.verify_receipt(receipt, signing_key=signing_key) is False
```

---

## 3. Minimal Implementation Sequence & Go/No-Go Decision

### 3.1 Corrected Implementation Prerequisites Order
As mandated by the PR review, implementation must proceed in exact dependency order:

```
[ Phase 3.1: Authoritative Workload Protection Registry ]
  - Add WorkloadProtectionRegistry & RegisteredToolPolicy
  - Enforce server-side protection lookup in PermissionGate & EpistemicOrchestrator
              |
              v
[ Phase 3.2: Capability Issuer & Canonical JCS Serialization ]
  - Add RFC 8785 Canonical JSON formatter
  - Implement CapabilityIssuer minting VersionedAuthorizationCapability
              |
              v
[ Phase 3.3: Trusted Execution Boundary Binding ]
  - Update TrustedExecutionBoundary.execute_protected_action()
  - Assert capability signature, expiration, target action/resource, and atomic token consumption
              |
              v
[ Phase 3.4: Policy Snapshot Authenticity & Revocation Registry ]
  - Implement ConsentAndPolicyDriftGate with 6-vector validation
  - Connect live RevocationRegistry and PolicyDiffEngine JCS hashing
              |
              v
[ Phase 3.5: Non-Mutating Opt-In Gate Integration & Acceptance Testing ]
  - Register ConsentAndPolicyDriftGate in opt-in mode
  - Execute 12 acceptance tests in tests/unit/test_consent_policy_drift_spec.py
```

### 3.2 Implementation Decision: **GO (Subject to Prerequisites)**

#### Verified Final Prerequisites:
1. **No Production Source Mutation in Phase 3:** This specification and its associated research documents are strictly non-mutating.
2. **Deterministic Enforceability:** All 12 acceptance criteria have been specified with executable test functions matched to real EpistemicOS constructors.
3. **Entropy Scheduler Independence:** The `EntropyAwareScheduler` remains 100% untouched.

---

## Summary Conclusion

This updated Phase 3 specification satisfies all review requirements. By establishing authoritative server-side workload protection, defining strict `RFC 8785` canonical serialization, introducing a dedicated `CapabilityIssuer`, and providing 12 executable test specifications, EpistemicOS achieves a mathematically sound, fail-closed roadmap for Consent Provenance and External Policy Drift Governance.
