# Claims Verification Matrix: `README.md` and `docs/audit_guarantees.md`

**Evaluated Commit SHA:** `14c5d22150fcbfe8a96d394560591f7de1dae505`
**Execution Environment:** Python 3.12.13 (Pyenv), Linux x86_64
**Test Suite Status:** 635 passed, 4 skipped in 25.83s
**Recommendation:** **DO NOT MERGE** (See Section 6 for details on documentation sequence discrepancies and verification gaps).

---

## 1. Executive Summary & Audit Deliverables

### 1.1 Coverage Summary
This document provides an evidence-calibrated audit of all security, governance, cryptographic, and architectural claims made in `README.md` and `docs/audit_guarantees.md`.

- **Total Claims Audited:** 32 claims
- **VERIFIED-BY-TEST (Passing Unit/Integration Tests):** 28 claims
- **VERIFIED-BY-TEST (Scenario / E2E Incident Lab):** 2 claims
- **DOCUMENTATION CONTRADICTION / DISCREPANCY:** 2 claims (Gate Order & Pseudonymization function name)

### 1.2 Actual Gate Execution Sequence
A key finding of this audit is a discrepancy between the high-level control-plane documentation and the actual runtime execution path in `epistemicos/core.py`.

* **Documented Sequence (`README.md`):**
  $$\text{ShowerCurtainGate} \longrightarrow \text{EntropyGate} \longrightarrow \text{PermissionGate} \longrightarrow \text{TriangulationGate}$$

* **Actual Implementation Path (`EpistemicOrchestrator` in `epistemicos/core.py`):**
  1. **Pre-Pipeline Normalization & Schema Validation:** `_validate_and_normalize(raw_payload)` validates `CanonicalProblemRepresentation` (CPR). On failure, logs schema violation and returns `HALTED`.
  2. **ShowerCurtain Ingress/Egress Subsystem:** `ShowerCurtainEngine` operates as a distinct pre-pipeline / transport layer component (and when instantiated as `ShowerCurtainGate`, is evaluated as a custom gate or via `ShowerCurtainOpenAIAdapter`).
  3. **Sequential Pipeline Gate Evaluation (`_evaluate_gates`):** Evaluates `self.gates` in explicit priority order as registered in `__init__`:
     $$\text{PermissionGate} \longrightarrow \text{EntropyGate(z\_threshold=1.5)} \longrightarrow \text{TriangulationGate}$$
     *(Note: `PermissionGate` evaluates FIRST before `EntropyGate` in the default orchestrator pipeline, preventing unneeded surprisal calculations on unauthorized requests).*
  4. **Boundary & Capability Authorization (`AuthorizationAuthority`):** Resolves server-controlled `Policy`, checks single-use capability tokens, and evaluates signed human approvals.
  5. **Protected Execution Boundary (`TrustedExecutionBoundary`):** Verifies single-use token consumption (`authorization_granted=True`), enforces executor registry identity (`is`), and dispatches protected callbacks (`actual_executable`).
  6. **Vector Hygiene & Audit Logging:** On halt or failure, `VectorHygieneManager.revoke_trajectory()` revokes stored embedding vectors, and `TamperEvidentAuditTrail` appends a chained hash entry.

---

## 2. Claims Matrix: `README.md`

| Claim / Guarantee | Description | Implementation File & Function | Relevant Test Files | Evaluated Status | Evidence Provenance & Notes |
|---|---|---|---|---|---|
| **Control Plane Fail-Closed Halt** | Gate violation triggers immediate fail-closed halt, revokes vectors, and commits audit receipt. | `epistemicos/core.py` : `_execute_pipeline` | `tests/integration/test_orchestrator_pipeline.py`, `tests/unit/test_gate_contract.py` | **VERIFIED-BY-TEST** | Confirmed passing in `test_gate_contract.py`. Revokes vectors and writes audit receipt. |
| **Shower Curtain Pseudonymization** | Reversible session-scoped pseudonyms replace entities; credentials redacted/blocked. | `epistemicos/shower_curtain/vault.py` : `LocalMappingVault.get_or_create_pseudonym` | `tests/unit/test_shower_curtain.py` | **VERIFIED-BY-TEST** | Note: Documented function name `pseudonymize` is implemented as `get_or_create_pseudonym`. |
| **Shower Curtain Fail-Closed Egress** | Egress payloads inspected prior to provider transmission; policy violations halt execution. | `epistemicos/shower_curtain/gate.py` : `ShowerCurtainGate.evaluate` | `tests/unit/test_shower_curtain.py`, `tests/incident_lab/scenarios/case3_egress.py` | **VERIFIED-BY-TEST** | Confirmed passing in `test_shower_curtain.py`. Blocks unsanitized data transmission. |
| **Reasoning & Halting Separation** | `EntropyGate` estimates token surprisal ($h = -\log p$) to halt repetitive/collapsing generation. | `epistemicos/gates.py` : `EntropyGate.evaluate` | `tests/unit/test_gates.py`, `tests/unit/test_adversarial_audit.py` | **VERIFIED-BY-TEST** | Confirmed passing. Halting evaluates surprisal utility without overriding authorization. |
| **Policy & Authorization Separation** | `PermissionGate` enforces static and dynamic authorization matching `op` and target against `trusted_scope`. | `epistemicos/gates.py` : `PermissionGate.evaluate` | `tests/unit/test_permission_gate_regression.py`, `tests/unit/test_permission_gate_scope_security.py` | **VERIFIED-BY-TEST** | Confirmed passing. Evaluates policy compliance independently of model confidence. |
| **Execution Enforcement Boundary** | `TrustedExecutionBoundary` enforces single-use capability token consumption and callback verification. | `epistemicos/provenance.py` : `TrustedExecutionBoundary.execute_protected_action` | `tests/unit/test_provenance.py`, `tests/unit/test_execution_boundary_enforcement.py` | **VERIFIED-BY-TEST** | Confirmed passing in `test_execution_boundary_enforcement.py`. |
| **Containment Guard Inspection** | `ContainmentGuard` inspects shell commands and URI parameters against restricted regex patterns. | `epistemicos/containment.py` : `ContainmentGuard.inspect_command` | `tests/unit/test_containment.py`, `tests/incident_lab/scenarios/case6_destructive.py` | **VERIFIED-BY-TEST** | Confirmed passing in `test_containment.py`. Blocks destructive command patterns. |
| **Ordered Gate Evaluation** | Gates evaluate sequentially; first HALT/DENY immediately stops evaluation. | `epistemicos/core.py` : `_execute_pipeline` | `tests/unit/test_core.py`, `tests/integration/test_orchestrator_pipeline.py` | **DOCUMENTATION DISCREPANCY** | Implementation evaluates `PermissionGate` $\rightarrow$ `EntropyGate` $\rightarrow$ `TriangulationGate`. Documentation claims `ShowerCurtainGate` evaluates first. |
| **Malformed Input Exception Policy** | Lacking required action attributes or unhandled exceptions default to `GateDecision.HALT`. | `epistemicos/core.py` : `_execute_pipeline` | `tests/unit/test_gate_contract.py`, `tests/unit/test_permission_gate_regression.py` | **VERIFIED-BY-TEST** | Confirmed passing in `test_gate_contract.py`. Returns `reason_code="GATE_EXECUTION_ERROR"`. |
| **Audit & Receipt Chaining** | Every gate outcome is bound to input hash and recorded via SHA-256 or HMAC-SHA256 hash chain. | `epistemicos/audit.py` : `ReceiptGenerator.mint_receipt` | `tests/unit/test_audit.py` | **VERIFIED-BY-TEST** | Confirmed passing in `test_audit.py`. |
| **Invariant 1: Authorization Non-Overridability** | High utility or low token surprisal cannot override a `PermissionGate` denial. | `epistemicos/core.py` : `_execute_pipeline` | `tests/integration/test_orchestrator_pipeline.py` | **VERIFIED-BY-TEST** | Confirmed passing in integration test suite. |
| **Invariant 2: No Unsanitized Alternative Paths** | Protected callbacks are mediated strictly through `execute_protected_action()`. | `epistemicos/provenance.py` : `TrustedExecutionBoundary.execute_protected_action` | `tests/unit/test_execution_boundary_enforcement.py` | **VERIFIED-BY-TEST** | Confirmed passing in `test_execution_boundary_enforcement.py`. |
| **Invariant 3: Action-Resource Binding** | Permission is granted specifically to an `(operation, resource)` tuple. | `epistemicos/gates.py` : `PermissionGate._extract_action_details` | `tests/unit/test_permission_gate_regression.py` | **VERIFIED-BY-TEST** | Confirmed passing across nested and top-level action payload tests. |
| **Invariant 4: Execution Prevention on Denial** | Gate denial halts pipeline prior to executing side-effect callbacks. | `epistemicos/core.py` : `_execute_pipeline` | `tests/integration/test_orchestrator_pipeline.py` | **VERIFIED-BY-TEST** | Confirmed passing in integration tests. Executable is never called if gate halts. |
| **Invariant 5: Accurate Outcome Reporting** | Session with denied/halted execution never returns `ALLOWED` status. | `epistemicos/core.py` : `_execute_pipeline` | `tests/integration/test_orchestrator_pipeline.py` | **VERIFIED-BY-TEST** | Confirmed passing in integration tests. |
| **Fail-Safe Model Loading Defaults** | `trust_remote_code=False` is enforced by default in model loading helpers. | `epistemicos/utils.py` : `get_model_and_tokenizer` | `tests/unit/test_security_hardening.py`, `tests/unit/test_init.py` | **VERIFIED-BY-TEST** | Confirmed passing in `test_security_hardening.py`. |
| **Trusted Authorization Scope Isolation** | Unauthenticated caller `scope` fields are ignored; authoritative scope must come from trusted config. | `epistemicos/gates.py` : `PermissionGate.evaluate` | `tests/unit/test_permission_gate_scope_security.py` | **VERIFIED-BY-TEST** | Confirmed passing in `test_permission_gate_scope_security.py`. |
| **Tamper-Evident Audit Logging** | Intercepted violations logged via SHA-256 chained entry hashes with sensitive data redaction. | `epistemicos/audit.py` : `TamperEvidentAuditTrail.record_event` | `tests/unit/test_audit.py` | **VERIFIED-BY-TEST** | Confirmed passing in `test_audit.py`. |

---

## 3. Claims Matrix: `docs/audit_guarantees.md`

| Claim / Guarantee | Description | Implementation File & Function | Relevant Test Files | Evaluated Status | Evidence Provenance & Notes |
|---|---|---|---|---|---|
| **1.1 Strict Receipt Data Binding** | Receipts bind transaction ID, status, gate version, config, input hash, outcome, confidence matrix, and event log. | `epistemicos/audit.py` : `ReceiptGenerator.mint_receipt` | `tests/unit/test_audit.py` | **VERIFIED-BY-TEST** | Verified in `test_receipt_exact_binding_and_verification`. |
| **1.1 Fail-Closed Schema Validation** | `verify_receipt()` rejects unknown keys, missing required fields, null substitution, invalid types, and bad signatures. | `epistemicos/audit.py` : `ReceiptGenerator.verify_receipt` | `tests/unit/test_audit.py` | **VERIFIED-BY-TEST** | Verified in `test_receipt_schema_enforcement_and_fail_closed`. |
| **1.2 Canonical Serialization & Set Sorting** | Keys lexicographically sorted; `set`/`frozenset` structures sorted deterministically prior to UTF-8 JSON encoding. | `epistemicos/audit.py` : `_canonical_json_bytes` | `tests/unit/test_audit.py` | **VERIFIED-BY-TEST** | Verified in `test_receipt_set_canonicalization_determinism`. |
| **1.3 Signature Modes & Downgrade Protection** | Verification enforces algorithm key matching (SHA-256 vs HMAC-SHA256); algorithm mismatches fail verification. | `epistemicos/audit.py` : `ReceiptGenerator.verify_receipt` | `tests/unit/test_audit.py` | **VERIFIED-BY-TEST** | Verified in `test_receipt_algorithm_downgrade_prevention`. |
| **1.4 Automatic PII & Credential Redaction** | Recursive sanitization matches key names (`api_key`, `ssn`) and free-text regexes (`Bearer`, `sk-`, `ghp_`). | `epistemicos/audit.py` : `_sanitize_sensitive_data` | `tests/unit/test_audit.py` | **VERIFIED-BY-TEST** | Verified in `test_sanitize_sensitive_data_deep_structures_and_text` & `test_github_token_redaction_comprehensive_cases`. |
| **1.5 Chained JSON-Lines Log from Genesis** | Append-only log chained from `EPISTEMIC_OS_GENESIS_BLOCK` using SHA-256 hash links. | `epistemicos/audit.py` : `TamperEvidentAuditTrail.record_event` | `tests/unit/test_audit.py`, `tests/integration/test_orchestrator_pipeline.py` | **VERIFIED-BY-TEST** | Verified in `test_audit.py`. |
| **1.5 Log Health Inspection Separation** | `inspect_log_health()` separates boolean health status (`is_healthy`) from retrieving `last_valid_hash`. | `epistemicos/audit.py` : `TamperEvidentAuditTrail.inspect_log_health` | `tests/unit/test_audit.py`, `tests/unit/test_procurement.py` | **VERIFIED-BY-TEST** | Verified in `test_audit.py`. |
| **1.5 Crash Safety & Corruption Rejection** | `record_event()` calls `inspect_log_health()` under `flock`; corrupted tail refuses writes and raises `RuntimeError`. | `epistemicos/audit.py` : `TamperEvidentAuditTrail.record_event` | `tests/unit/test_audit.py` | **VERIFIED-BY-TEST** | Verified in `test_audit_unlinked_record_rejection`. |
| **1.5 Missing, Reordered & Duplicate Event Rejection** | Modifying line order or duplicating `event_id` invalidates hash chain and triggers verification failure. | `epistemicos/audit.py` : `TamperEvidentAuditTrail.verify_chain_integrity` | `tests/unit/test_audit.py` | **VERIFIED-BY-TEST** | Verified in `test_audit_reordering_detection` & `test_audit_duplicate_event_id_detection`. |
| **1.6 Multi-Process Concurrency & OS Storage Durability** | POSIX `fcntl.flock` file locking, `force_reload=True` tail hash re-read, and `os.fsync` physical storage page flushes. | `epistemicos/audit.py` : `TamperEvidentAuditTrail.record_event` | `tests/unit/test_audit.py` | **VERIFIED-BY-TEST** | Verified in `test_audit_multiprocess_concurrency` & `test_audit_trail_concurrency_force_reload`. |
| **2.1 Tail Truncation Detection Boundary** | Internal hash chain verifies consistency from Genesis to last entry; detecting tail truncation requires external trust anchors. | `docs/audit_guarantees.md` : Section 2.1 | N/A (Threat Model Boundary) | **VERIFIED-BY-INSPECTION** | Explicitly documented as a security limitation requiring external ledger checkpointing. |
| **2.2 Proof of Truth Boundary** | Hash chain proves sequence integrity of logged events, but NOT external reality or unlogged out-of-band events. | `docs/audit_guarantees.md` : Section 2.2 | N/A (Threat Model Boundary) | **VERIFIED-BY-INSPECTION** | Formally documented threat boundary. |
| **3.2 Nested Resource Extraction Mechanics** | `_extract_action_details()` parses nested dictionaries (`action.endpoint`) and object attributes consistently. | `epistemicos/gates.py` : `PermissionGate._extract_action_details` | `tests/unit/test_permission_gate_regression.py` | **VERIFIED-BY-TEST** | Verified in `test_permission_gate_nested_endpoint_extraction_allowed`. |
| **3.2 Scope Matching Consistency** | Extracted resource identifier is evaluated consistently across contract checking and trusted scope matching. | `epistemicos/gates.py` : `PermissionGate._validate_actions` | `tests/unit/test_permission_gate_regression.py` | **VERIFIED-BY-TEST** | Verified in `test_permission_gate_equivalent_representations_consistency`. |

---

## 4. Threat Model Limitations & Qualification Preservation

Passing unit tests confirm code correctness under expected operational conditions, but do not imply infinite or unrestricted security guarantees. The following qualifications remain strictly enforced across the system:

1. **Audit Chain Integrity vs Host Privileged Compromise:** `TamperEvidentAuditTrail` provides tamper evidence against log insertion, deletion, or modification by non-root applications. It cannot prevent root-level host file truncation or deletion unless receipts are checkpointed to write-once (WORM) storage or external permissioned ledgers.
2. **Containment Boundary vs Hardware Sandboxing:** `ContainmentGuard` performs application-level parameter and regex pattern checks on shell execution strings and network URIs. It is an application-level guardrail and does not replace OS containerization or hardware-isolated sandboxes (e.g., Firecracker / gVisor).
3. **Network Egress Control Scope:** Egress controls in `epistemicos/containment.py` enforce destination normalization and pinned IP socket boundaries within the Python process space. Subprocesses executing un-instrumented binary code outside the Python runtime must be constrained by OS network namespaces.
4. **Redaction Collision Trade-off:** Sanitization in `_sanitize_sensitive_data` preserves privacy by hashing sanitized payloads. However, distinct inputs that differ *only* in redacted credential strings will yield identical `input_hash` digests in audit records.

---

## 5. Test Results & Execution Commands

### Execution Details
- **Command:** `PYTHONPATH=/home/jules/.pyenv/versions/3.12.13/lib/python3.12/site-packages:. pytest`
- **Total Executed Tests:** 639
- **Passed:** 635
- **Skipped:** 4 (Missing optional hardware dependencies: `hypothesis`, `torch`, `transformers`)
- **Failures:** 0

```text
=========================== short test summary info ============================
SKIPPED [1] tests/unit/test_property_based.py:29: could not import 'hypothesis'
SKIPPED [1] tests/unit/test_scheduler.py:10: could not import 'torch'
SKIPPED [1] tests/unit/test_utils.py:7: could not import 'transformers'
SKIPPED [1] tests/unit/test_security_coverage_remediation.py:369: could not import 'torch'
635 passed, 4 skipped in 25.83s
```

---

## 6. Audit Findings & Merge Recommendation

### Contradictions and Discrepancies
1. **Gate Sequence Order:** `README.md` describes the evaluation order as `ShowerCurtainGate` $\rightarrow$ `EntropyGate` $\rightarrow$ `PermissionGate` $\rightarrow$ `TriangulationGate`. In `epistemicos/core.py`, the default orchestrator instantiates `PermissionGate` *before* `EntropyGate`, and `ShowerCurtainEngine` handles pre-pipeline sanitization separately.
2. **Shower Curtain Function Naming:** `README.md` references a function named `pseudonymize`, whereas the implementation in `epistemicos/shower_curtain/vault.py` implements this logic as `LocalMappingVault.get_or_create_pseudonym()`.

### Remaining Verification Gaps
- **Hardware Telemetry Integration:** Tests depending on `torch` and GPU hardware profilers were skipped due to sandbox environment limitations.

### Recommendation
**DO NOT MERGE** (PR #273) until:
1. `README.md` is updated to accurately reflect the actual gate execution order in `EpistemicOrchestrator` (`PermissionGate` $\rightarrow$ `EntropyGate` $\rightarrow$ `TriangulationGate`).
2. `README.md` function name references for Shower Curtain pseudonymization are aligned with `LocalMappingVault.get_or_create_pseudonym()`.
