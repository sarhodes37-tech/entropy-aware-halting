# Claims Verification Matrix: `README.md` and `docs/audit_guarantees.md`

This document verifies every claim made in `README.md` and `docs/audit_guarantees.md` regarding system guarantees, security boundaries, cryptographic properties, fail-closed mechanics, and architectural invariants against the EpistemicOS codebase.

---

## 1. Claims from `README.md`

### 1.1 System Architecture & Control Plane Implementation
| Claim / Guarantee | Description | File | Function / Component | Status | Verification Notes |
|---|---|---|---|---|---|
| **Fail-Closed Gate Violation Halt** | Any gate violation triggers an immediate fail-closed halt, revokes execution vectors, and commits an audit receipt. | `epistemicos/core.py` | `EpistemicOrchestrator._execute_pipeline` | **VERIFIED-BY-TEST** | Verified in `tests/integration/test_orchestrator_pipeline.py` & `tests/unit/test_gate_contract.py`. |
| **Shower Curtain Session Pseudonyms** | Reversible pseudonyms replace identifiable entities within isolated session scopes. Secrets are strictly redacted/blocked. | `epistemicos/shower_curtain/vault.py` | `LocalMappingVault.get_or_create_pseudonym` | **VERIFIED-BY-TEST** | Verified in `tests/unit/test_shower_curtain.py`. |
| **Shower Curtain Fail-Closed Egress** | Egress payloads are serialized and inspected prior to transmission; unsanitized data or policy violations trigger immediate halts. | `epistemicos/shower_curtain/gate.py` | `ShowerCurtainGate.evaluate` | **VERIFIED-BY-TEST** | Verified in `tests/unit/test_shower_curtain.py` & `tests/incident_lab/scenarios/case3_egress.py`. |

### 1.2 Control Plane Mechanics & Architectural Invariants
| Claim / Guarantee | Description | File | Function / Component | Status | Verification Notes |
|---|---|---|---|---|---|
| **Reasoning & Halting Separation** | `EntropyGate` / `EntropyAwareScheduler` estimates token surprisal and semantic uncertainty to determine halting based on computational utility. | `epistemicos/gates.py` | `EntropyGate.evaluate` | **VERIFIED-BY-TEST** | Verified in `tests/unit/test_gates.py` & `tests/unit/test_adversarial_audit.py`. |
| **Policy & Authorization Separation** | `PermissionGate` enforces static and dynamic authorization contracts matching requested operations and targets against trusted scope. | `epistemicos/gates.py` | `PermissionGate.evaluate` | **VERIFIED-BY-TEST** | Verified in `tests/unit/test_permission_gate_regression.py` & `tests/unit/test_permission_gate_scope_security.py`. |
| **Execution Enforcement & Token Revocation** | `TrustedExecutionBoundary` mediates action dispatching enforcing explicit tokens, single-use consumption, and callback verification. `ContainmentGuard` inspects shell commands and URIs. | `epistemicos/provenance.py` / `epistemicos/containment.py` | `TrustedExecutionBoundary.execute_protected_action` / `ContainmentGuard.inspect_command` | **VERIFIED-BY-TEST** | Verified in `tests/unit/test_provenance.py`, `tests/unit/test_execution_boundary_enforcement.py`, & `tests/unit/test_containment.py`. |
| **Ordered Sequential Fail-Closed Gates** | Gates evaluate sequentially (`ShowerCurtainGate` $\rightarrow$ `EntropyGate` $\rightarrow$ `PermissionGate` $\rightarrow$ `TriangulationGate`); first HALT/DENY immediately stops evaluation. | `epistemicos/core.py` | `EpistemicOrchestrator._execute_pipeline` | **VERIFIED-BY-TEST** | Verified in `tests/unit/test_core.py` & `tests/integration/test_orchestrator_pipeline.py`. |
| **Malformed Inputs & Exceptions Default to HALT** | Lacking required action contract attributes or encountering unhandled exceptions defaults to `GateDecision.HALT`. | `epistemicos/core.py` | `EpistemicOrchestrator._execute_pipeline` | **VERIFIED-BY-TEST** | Verified in `tests/unit/test_gate_contract.py` & `tests/unit/test_permission_gate_regression.py`. |
| **Audit & Receipt Binding** | Every gate outcome is cryptographically bound to input hash and recorded in `TamperEvidentAuditTrail` via SHA-256 hash chain or HMAC. | `epistemicos/audit.py` | `ReceiptGenerator.mint_receipt` | **VERIFIED-BY-TEST** | Verified in `tests/unit/test_audit.py`. |
| **Invariant 1: Authorization Non-Overridability** | High utility or low surprisal cannot override a `PermissionGate` denial. | `epistemicos/core.py` | `EpistemicOrchestrator._execute_pipeline` | **VERIFIED-BY-TEST** | Verified in `tests/integration/test_orchestrator_pipeline.py`. |
| **Invariant 2: No Unsanitized Alternative Execution Paths** | Workload callbacks are mediated strictly through `TrustedExecutionBoundary.execute_protected_action()`. | `epistemicos/provenance.py` | `TrustedExecutionBoundary.execute_protected_action` | **VERIFIED-BY-TEST** | Verified in `tests/unit/test_execution_boundary_enforcement.py`. |
| **Invariant 3: Action-Resource Binding** | Authorization is granted specifically to `(operation, resource)` tuple extracted via `_extract_action_details()`. | `epistemicos/gates.py` | `PermissionGate._extract_action_details` | **VERIFIED-BY-TEST** | Verified in `tests/unit/test_permission_gate_regression.py`. |
| **Invariant 4: Execution Prevention on Denial** | Gate denial immediately halts pipeline execution prior to side-effect dispatch. | `epistemicos/core.py` | `EpistemicOrchestrator._execute_pipeline` | **VERIFIED-BY-TEST** | Verified in `tests/integration/test_orchestrator_pipeline.py`. |
| **Invariant 5: Accurate Outcome Reporting** | Final status reporting reflects actual execution outcomes; denied/halted sessions never return ALLOWED. | `epistemicos/core.py` | `EpistemicOrchestrator._execute_pipeline` | **VERIFIED-BY-TEST** | Verified in `tests/integration/test_orchestrator_pipeline.py`. |

### 1.3 Security Hardening & Scope Isolation
| Claim / Guarantee | Description | File | Function / Component | Status | Verification Notes |
|---|---|---|---|---|---|
| **Fail-Safe Model Loading Defaults** | `trust_remote_code=False` is enforced by default in model loading helpers. | `epistemicos/utils.py` | `get_model_and_tokenizer` | **VERIFIED-BY-TEST** | Verified in `tests/unit/test_security_hardening.py` & `tests/unit/test_init.py`. |
| **Trusted Scope Boundary Isolation** | `PermissionGate` ignores request-supplied scope parameters in unauthenticated payloads; authoritative scope must come from trusted config. | `epistemicos/gates.py` | `PermissionGate.evaluate` | **VERIFIED-BY-TEST** | Verified in `tests/unit/test_permission_gate_scope_security.py`. |
| **Tamper-Evident Audit Logging & Sanitization** | Intercepted violations are logged via SHA-256 chained entry hashes after sanitization of PII/credentials. | `epistemicos/audit.py` | `TamperEvidentAuditTrail.record_event` | **VERIFIED-BY-TEST** | Verified in `tests/unit/test_audit.py`. |

---

## 2. Claims from `docs/audit_guarantees.md`

### 2.1 Section 1: Guarantees Provided by Implementation
| Claim / Guarantee | Description | File | Function / Component | Status | Verification Notes |
|---|---|---|---|---|---|
| **1.1 Strict Receipt Data Binding & Schema Enforcement** | Receipts bind transaction ID, status, gate version, config, input hash, details, outcome, confidence matrix, event log, and signature. | `epistemicos/audit.py` | `ReceiptGenerator.mint_receipt` | **VERIFIED-BY-TEST** | Verified in `tests/unit/test_audit.py` (`test_receipt_exact_binding_and_verification`). |
| **1.1 Fail-Closed Schema Validation** | `verify_receipt()` rejects unknown fields, missing required fields, null substitution, invalid types, and malformed signature formats. | `epistemicos/audit.py` | `ReceiptGenerator.verify_receipt` | **VERIFIED-BY-TEST** | Verified in `tests/unit/test_audit.py` (`test_receipt_schema_enforcement_and_fail_closed`). |
| **1.2 Canonical Serialization & Set/Frozenset Sorting** | Keys lexicographically sorted; `set` and `frozenset` non-native structures converted into sorted lists prior to UTF-8 JSON serialization. | `epistemicos/audit.py` | `_canonical_json_bytes` | **VERIFIED-BY-TEST** | Verified in `tests/unit/test_audit.py` (`test_receipt_set_canonicalization_determinism`). |
| **1.3 Signature Modes & Downgrade Protection** | SHA-256 vs HMAC-SHA256 modes enforced; key presence requires HMAC-SHA256 and algorithm mismatch fails verification. | `epistemicos/audit.py` | `ReceiptGenerator.verify_receipt` | **VERIFIED-BY-TEST** | Verified in `tests/unit/test_audit.py` (`test_receipt_algorithm_downgrade_prevention`). |
| **1.4 Automatic PII & Credential Redaction** | Key name matching and free-text regex scanning redact API keys, Bearer tokens, credentials, and sensitive fields recursively. | `epistemicos/audit.py` | `_sanitize_sensitive_data` | **VERIFIED-BY-TEST** | Verified in `tests/unit/test_audit.py` (`test_sanitize_sensitive_data_deep_structures_and_text` & `test_audit_sensitive_data_redaction`). |
| **1.5 Chained JSON-Lines Log from Genesis** | Append-only JSON-Lines log chained cryptographically from `EPISTEMIC_OS_GENESIS_BLOCK`. | `epistemicos/audit.py` | `TamperEvidentAuditTrail.record_event` | **VERIFIED-BY-TEST** | Verified in `tests/unit/test_audit.py` & `tests/integration/test_orchestrator_pipeline.py`. |
| **1.5 Log Health Inspection Separation** | `inspect_log_health()` separates log health status (`is_healthy: bool`) from retrieving last valid entry hash (`last_valid_hash: str`). | `epistemicos/audit.py` | `TamperEvidentAuditTrail.inspect_log_health` | **VERIFIED-BY-TEST** | Verified in `tests/unit/test_audit.py` & `tests/unit/test_procurement.py`. |
| **1.5 Crash Safety & Explicit Corruption Rejection** | `record_event()` calls `inspect_log_health()` under file lock; corrupt/tampered tail refuses write and raises `RuntimeError`. | `epistemicos/audit.py` | `TamperEvidentAuditTrail.record_event` | **VERIFIED-BY-TEST** | Verified in `tests/unit/test_audit.py` (`test_audit_unlinked_record_rejection`). |
| **1.5 Missing, Reordered & Duplicate Event Rejection** | Deleting/reordering lines invalidates prior hash links; duplicate `event_id` entries are tracked and rejected. | `epistemicos/audit.py` | `TamperEvidentAuditTrail.verify_chain_integrity` | **VERIFIED-BY-TEST** | Verified in `tests/unit/test_audit.py` (`test_audit_reordering_detection` & `test_audit_duplicate_event_id_detection`). |
| **1.6 Multi-Process Concurrency & OS Durability** | POSIX `fcntl.flock` file locking, `force_reload=True` tail hash re-read, and `os.fsync` disk page flushing on write. | `epistemicos/audit.py` | `TamperEvidentAuditTrail.record_event` | **VERIFIED-BY-TEST** | Verified in `tests/unit/test_audit.py` (`test_audit_multiprocess_concurrency` & `test_audit_trail_concurrency_force_reload`). |

### 2.2 Section 3: Authorization Scope & Nested Resource Extraction Mechanics
| Claim / Guarantee | Description | File | Function / Component | Status | Verification Notes |
|---|---|---|---|---|---|
| **3.2 Nested Resource Target Extraction** | `_extract_action_details()` inspects `endpoint`, `node`, `policy`, `resource`, `target` inside nested dictionary/object structures. | `epistemicos/gates.py` | `PermissionGate._extract_action_details` | **VERIFIED-BY-TEST** | Verified in `tests/unit/test_permission_gate_regression.py` (`test_permission_gate_nested_endpoint_extraction_allowed`). |
| **3.2 Scope Matching Consistency** | Resource validation against `allowed_resources` uses exact same extracted resource string across contract evaluation and scope checks. | `epistemicos/gates.py` | `PermissionGate._validate_actions` | **VERIFIED-BY-TEST** | Verified in `tests/unit/test_permission_gate_regression.py` (`test_permission_gate_equivalent_representations_consistency`). |
