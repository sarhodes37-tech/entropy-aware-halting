# Claims Verification Matrix & Security Audit: `README.md` and `docs/audit_guarantees.md`

**Evaluated Source Commit SHA:** `14c5d22150fcbfe8a96d394560591f7de1dae505` (Base HEAD & PR HEAD)
**Execution Environment:** Python 3.12.13 (Pyenv), Linux x86_64
**Full Test Suite Result:** `635 passed, 4 skipped in 25.55s`
**Final Merge Recommendation:** **DO NOT MERGE** (Documentation sequence discrepancies and conceptual term mismatches require explicit follow-up in documentation updates).

---

## 1. Executive Summary & Audit Scope Reconciliation

### 1.1 Scope Reconciliation
This audit systematically evaluates all claims in `README.md` and `docs/audit_guarantees.md` across control-plane mechanics, security guarantees, architectural invariants, cryptographic audit properties, privacy controls, egress boundaries, defect analysis, and benchmark metrics.

- **Total Documented Claims Evaluated:** 34 distinct claims
- **Full Scope Coverage:** 100% of claims in `README.md` and `docs/audit_guarantees.md` are evaluated.
- **Explicit Exclusions:** None. All sections (including Section 1 guarantees, Section 2 trust-anchor boundaries, Section 3 resource extraction defect analysis, and Section 4 Phase 2 egress/side-effect controls) are explicitly included.

### 1.2 Fine-Grained Status Definitions
To prevent overstating security guarantees based solely on basic unit tests, statuses are calibrated using fine-grained classifications:

- **`VERIFIED-BY-UNIT-TEST`**: Claim is verified by isolated unit tests passing at commit `14c5d22150fcbfe8a96d394560591f7de1dae505`.
- **`VERIFIED-BY-INTEGRATION-TEST`**: Claim is verified across orchestrator pipeline integration test suites.
- **`VERIFIED-BY-SCENARIO-E2E`**: Claim is verified under realistic multi-step or Incident Lab adversarial red-team scenario test suites (`tests/incident_lab/`).
- **`PARTIALLY-SUPPORTED-LIMITATION`**: Feature is implemented and tested under specific conditions, but does not provide complete or unrestricted security guarantees (e.g. application-level regex vs kernel sandboxing; `os.fsync` vs underlying OS/disk caching policies).
- **`VERIFIED-BY-INSPECTION`**: Claim represents a documented threat-model boundary, design limitation, or non-functional invariant verified via code/documentation inspection.
- **`DOCUMENTATION-DISCREPANCY`**: Code implementation diverges from the exact wording or sequence described in the documentation.

---

## 2. Reconciled Gate Execution Sequence & Architecture

### 2.1 Runtime Control Plane Execution Path (`epistemicos/core.py`)
Tracing the execution path through `EpistemicOrchestrator.process_submission()` reveals that Shower Curtain data sanitization, governance gate evaluation, and boundary authorization operate as distinct, decoupled stages:

1. **Pre-Pipeline Normalization & Schema Validation:**
   `_validate_and_normalize(raw_payload)` attempts parsing into `CanonicalProblemRepresentation` (CPR). Schema or validation failures mask sensitive fields, log `CPR_Validation` failure in `TamperEvidentAuditTrail`, and return `{"status": "HALTED", "reason": "Schema validation failed"}` without evaluating gates.

2. **Shower Curtain Privacy Boundary (Transport / Pre-Pipeline Layer):**
   `ShowerCurtainEngine` operates as a separate local privacy boundary instantiated during orchestrator initialization (`self.shower_curtain = ShowerCurtainEngine(...)`). When prompt/egress payloads pass through `ShowerCurtainGate` or `ShowerCurtainOpenAIAdapter`, PII detection and session pseudonymization (`LocalMappingVault.get_or_create_pseudonym`) run prior to model inference.

3. **Sequential Pipeline Gate Evaluation (`_evaluate_gates`):**
   Pipeline gates in `self.gates` evaluate sequentially in explicit priority order as registered during `__init__`:
   $$\text{PermissionGate} \longrightarrow \text{EntropyGate(z\_threshold=1.5)} \longrightarrow \text{TriangulationGate}$$
   *Discrepancy Note:* `README.md` states the sequence as `ShowerCurtainGate` $\rightarrow$ `EntropyGate` $\rightarrow$ `PermissionGate` $\rightarrow$ `TriangulationGate`. In actual runtime code, `PermissionGate` evaluates *before* `EntropyGate` to prevent unnecessary surprisal computations on unauthorized operations.

4. **Boundary Authorization & Capability Issuance:**
   If a protected action is requested, `AuthorizationAuthority.evaluate_and_issue_capability()` evaluates the action against a server-controlled `Policy` (ignoring caller-supplied overrides) and issues a single-use `Capability` token bound to principal, operation, resource target, request digest, and expiration timestamp.

5. **Protected Execution Boundary (`TrustedExecutionBoundary`):**
   `TrustedExecutionBoundary.execute_protected_action()` verifies capability token validity, enforces exact callable object identity (`is`) in the trusted executor registry, atomically consumes the token, and executes the callback (`actual_executable`).

6. **Vector Hygiene & Audit Logging:**
   If any gate returns `HALT`/`DENY` or an exception occurs, `VectorHygieneManager.revoke_trajectory()` revokes stored trajectory embeddings, and `TamperEvidentAuditTrail.record_event()` appends a cryptographically chained JSON-Lines log entry.

---

## 3. Calibrated Claims Matrix: `README.md`

| Claim / Guarantee | Description | Implementation File & Function | Test Suite Evidence & Test Names | Calibrated Status | Evidence Provenance & Qualification Notes |
|---|---|---|---|---|---|
| **Control Plane Fail-Closed Halt** | Gate violation triggers immediate fail-closed halt, revokes vectors, and commits audit receipt. | `epistemicos/core.py` : `_execute_pipeline` | `tests/integration/test_orchestrator_pipeline.py` (`test_orchestrator_pipeline_halt`), `tests/unit/test_gate_contract.py` | **VERIFIED-BY-INTEGRATION-TEST** | Verified at commit `14c5d22150fcbfe8a96d394560591f7de1dae505`. Revokes trajectory vectors and commits audit entry. |
| **Shower Curtain Pseudonymization** | Reversible session-scoped pseudonyms replace entities; credentials redacted/blocked. | `epistemicos/shower_curtain/vault.py` : `LocalMappingVault.get_or_create_pseudonym` | `tests/unit/test_shower_curtain.py` (`test_vault_pseudonym_generation_and_rehydration`) | **DOCUMENTATION-DISCREPANCY** | `README.md` uses the conceptual term `pseudonymize`, whereas the implementation is `LocalMappingVault.get_or_create_pseudonym()`. |
| **Shower Curtain Fail-Closed Egress** | Unsanitized sensitive data or policy violations trigger immediate execution halts. | `epistemicos/shower_curtain/gate.py` : `ShowerCurtainGate.evaluate` | `tests/incident_lab/scenarios/case3_egress.py`, `tests/unit/test_shower_curtain.py` | **VERIFIED-BY-SCENARIO-E2E** | Scenario test confirms egress violation halts request and blocks downstream transmission. |
| **Reasoning & Halting Separation** | `EntropyGate` estimates token surprisal ($h = -\log p$) to halt repetitive/collapsing generation. | `epistemicos/gates.py` : `EntropyGate.evaluate` | `tests/unit/test_gates.py` (`test_entropy_gate_eval`), `tests/unit/test_adversarial_audit.py` | **VERIFIED-BY-UNIT-TEST** | Verified halting on high surprisal. Evaluates utility independently of authorization. |
| **Policy & Authorization Separation** | `PermissionGate` enforces static/dynamic authorization matching `op` and target against `trusted_scope`. | `epistemicos/gates.py` : `PermissionGate.evaluate` | `tests/unit/test_permission_gate_regression.py`, `tests/unit/test_permission_gate_scope_security.py` | **VERIFIED-BY-UNIT-TEST** | Verified matching against server-side scope. High utility cannot override permission denial. |
| **Execution Enforcement Boundary** | `TrustedExecutionBoundary` enforces single-use capability token consumption and executor verification. | `epistemicos/provenance.py` : `TrustedExecutionBoundary.execute_protected_action` | `tests/unit/test_execution_boundary_enforcement.py` (`test_single_use_token_consumption`) | **VERIFIED-BY-UNIT-TEST** | Single-use consumption verified. Tokens cannot be reused across requests. |
| **Containment Guard Parameter Inspection** | `ContainmentGuard` inspects shell commands and URI parameters against restricted regex patterns. | `epistemicos/containment.py` : `ContainmentGuard.inspect_command` | `tests/incident_lab/scenarios/case6_destructive.py`, `tests/unit/test_containment.py` | **PARTIALLY-SUPPORTED-LIMITATION** | Application-level regex parameter check. Does not replace OS/kernel hardware sandbox isolation. |
| **Ordered Gate Evaluation** | Gates evaluate sequentially; first HALT/DENY immediately stops evaluation. | `epistemicos/core.py` : `_execute_pipeline` | `tests/unit/test_core.py`, `tests/integration/test_orchestrator_pipeline.py` | **DOCUMENTATION-DISCREPANCY** | Actual pipeline executes `PermissionGate` $\rightarrow$ `EntropyGate` $\rightarrow$ `TriangulationGate`. `README.md` incorrectly lists `ShowerCurtainGate` first. |
| **Malformed Input Exception Policy** | Missing required attributes or unhandled gate exceptions default to `GateDecision.HALT`. | `epistemicos/core.py` : `_execute_pipeline` | `tests/unit/test_gate_contract.py` (`test_gate_exception_fails_closed`) | **VERIFIED-BY-UNIT-TEST** | Verified fail-closed exception handling with `reason_code="GATE_EXECUTION_ERROR"`. |
| **Audit & Receipt Binding** | Every gate outcome is bound to input hash and recorded via SHA-256 or HMAC-SHA256. | `epistemicos/audit.py` : `ReceiptGenerator.mint_receipt` | `tests/unit/test_audit.py` (`test_receipt_exact_binding_and_verification`) | **VERIFIED-BY-UNIT-TEST** | Binds transaction ID, status, gate version, input hash, and event log trace. |
| **Invariant 1: Authorization Non-Overridability** | High utility or low token surprisal cannot override a `PermissionGate` denial. | `epistemicos/core.py` : `_execute_pipeline` | `tests/integration/test_orchestrator_pipeline.py` (`test_permission_gate_denial_overrides_low_entropy`) | **VERIFIED-BY-INTEGRATION-TEST** | Confirmed non-compensatory constraint. |
| **Invariant 2: No Unsanitized Alternative Paths** | Protected callbacks are mediated strictly through `execute_protected_action()`. | `epistemicos/provenance.py` : `TrustedExecutionBoundary.execute_protected_action` | `tests/unit/test_execution_boundary_enforcement.py` | **VERIFIED-BY-UNIT-TEST** | Unauthenticated direct invocation routes are rejected. |
| **Invariant 3: Action-Resource Binding** | Permission is granted specifically to an `(operation, resource)` tuple. | `epistemicos/gates.py` : `PermissionGate._extract_action_details` | `tests/unit/test_permission_gate_regression.py` | **VERIFIED-BY-UNIT-TEST** | Evaluated across top-level, nested, and object-wrapped representations. |
| **Invariant 4: Execution Prevention on Denial** | Gate denial halts pipeline prior to executing side-effect callbacks. | `epistemicos/core.py` : `_execute_pipeline` | `tests/integration/test_orchestrator_pipeline.py` | **VERIFIED-BY-INTEGRATION-TEST** | Executable callback is never invoked if any gate returns HALT/DENY. |
| **Invariant 5: Accurate Outcome Reporting** | Session with denied/halted execution never returns `ALLOWED` status. | `epistemicos/core.py` : `_execute_pipeline` | `tests/integration/test_orchestrator_pipeline.py` | **VERIFIED-BY-INTEGRATION-TEST** | Verified status contract consistency. |
| **Fail-Safe Model Loading Defaults** | `trust_remote_code=False` is enforced by default in model loading helpers. | `epistemicos/utils.py` : `get_model_and_tokenizer` | `tests/unit/test_security_hardening.py` (`test_get_model_and_tokenizer_trust_remote_code_default`) | **VERIFIED-BY-UNIT-TEST** | Verified default flag value prevents unverified remote code execution. |
| **Trusted Scope Boundary Isolation** | Unauthenticated caller `scope` fields are ignored; authoritative scope must come from trusted config. | `epistemicos/gates.py` : `PermissionGate.evaluate` | `tests/unit/test_permission_gate_scope_security.py` | **VERIFIED-BY-UNIT-TEST** | Request-supplied scope fields in unauthenticated context are ignored. |
| **Tamper-Evident Audit Logging** | Intercepted violations logged via SHA-256 chained entry hashes with sensitive data redaction. | `epistemicos/audit.py` : `TamperEvidentAuditTrail.record_event` | `tests/unit/test_audit.py` (`test_audit_sensitive_data_redaction`) | **VERIFIED-BY-UNIT-TEST** | Verified hash-chain link updates and credential redaction. |

---

## 4. Calibrated Claims Matrix: `docs/audit_guarantees.md`

| Claim / Guarantee | Description | Implementation File & Function | Test Suite Evidence & Test Names | Calibrated Status | Evidence Provenance & Qualification Notes |
|---|---|---|---|---|---|
| **1.1 Strict Receipt Data Binding** | Receipts bind transaction ID, status, gate version, config, input hash, outcome, confidence matrix, and event log. | `epistemicos/audit.py` : `ReceiptGenerator.mint_receipt` | `tests/unit/test_audit.py` (`test_receipt_exact_binding_and_verification`) | **VERIFIED-BY-UNIT-TEST** | Verified canonical dictionary binding and HMAC signature calculation. |
| **1.1 Fail-Closed Schema Validation** | `verify_receipt()` rejects unknown keys, missing required fields, null substitution, invalid types, and bad signatures. | `epistemicos/audit.py` : `ReceiptGenerator.verify_receipt` | `tests/unit/test_audit.py` (`test_receipt_schema_enforcement_and_fail_closed`) | **VERIFIED-BY-UNIT-TEST** | Verified rejection of field injection, null substitution, and bad hex formats. |
| **1.2 Canonical Serialization & Set Sorting** | Keys lexicographically sorted; `set`/`frozenset` structures sorted deterministically prior to UTF-8 JSON encoding. | `epistemicos/audit.py` : `_canonical_json_bytes` | `tests/unit/test_audit.py` (`test_receipt_set_canonicalization_determinism`) | **VERIFIED-BY-UNIT-TEST** | Prevents runtime non-determinism across Python runtime executions. |
| **1.3 Signature Modes & Downgrade Protection** | Verification enforces algorithm key matching (SHA-256 vs HMAC-SHA256); algorithm mismatches fail verification. | `epistemicos/audit.py` : `ReceiptGenerator.verify_receipt` | `tests/unit/test_audit.py` (`test_receipt_algorithm_downgrade_prevention`) | **VERIFIED-BY-UNIT-TEST** | Verified algorithm downgrade rejection (e.g. key supplied for plain SHA-256 receipt fails). |
| **1.4 Automatic PII & Credential Redaction** | Recursive sanitization matches key names (`api_key`, `ssn`) and free-text regexes (`Bearer`, `sk-`, `ghp_`, `github_pat_`). | `epistemicos/audit.py` : `_sanitize_sensitive_data` | `tests/unit/test_audit.py` (`test_sanitize_sensitive_data_deep_structures_and_text`, `test_github_token_redaction_comprehensive_cases`) | **PARTIALLY-SUPPORTED-LIMITATION** | Effective regex/key matching. Trade-off: Hashing sanitized inputs means inputs differing *only* in secrets yield identical `input_hash`. |
| **1.5 Chained JSON-Lines Log from Genesis** | Append-only log chained from `EPISTEMIC_OS_GENESIS_BLOCK` using SHA-256 hash links. | `epistemicos/audit.py` : `TamperEvidentAuditTrail.record_event` | `tests/integration/test_orchestrator_pipeline.py`, `tests/test_benchmark_audit.py` | **VERIFIED-BY-INTEGRATION-TEST** | Sequential entry hashing verified across multi-event pipelines. |
| **1.5 Log Health Inspection Separation** | `inspect_log_health()` separates boolean health status (`is_healthy`) from retrieving `last_valid_hash`. | `epistemicos/audit.py` : `TamperEvidentAuditTrail.inspect_log_health` | `tests/unit/test_audit.py`, `tests/unit/test_procurement.py` | **VERIFIED-BY-UNIT-TEST** | Prevents appending to corrupted or partially written log tails. |
| **1.5 Crash Safety & Corruption Rejection** | `record_event()` calls `inspect_log_health()` under `flock`; corrupted tail refuses writes and raises `RuntimeError`. | `epistemicos/audit.py` : `TamperEvidentAuditTrail.record_event` | `tests/unit/test_audit.py` (`test_audit_unlinked_record_rejection`) | **VERIFIED-BY-UNIT-TEST** | Verified refusal to append to damaged log files. |
| **1.5 Missing, Reordered & Duplicate Event Rejection** | Modifying line order or duplicating `event_id` invalidates hash chain and triggers verification failure. | `epistemicos/audit.py` : `TamperEvidentAuditTrail.verify_chain_integrity` | `tests/unit/test_audit.py` (`test_audit_reordering_detection`, `test_audit_duplicate_event_id_detection`) | **VERIFIED-BY-UNIT-TEST** | Verified line swap and duplicate detection. |
| **1.6 Multi-Process Concurrency & OS Storage Durability** | POSIX `fcntl.flock` file locking, `force_reload=True` tail hash re-read, and `os.fsync` physical storage page flushes. | `epistemicos/audit.py` : `TamperEvidentAuditTrail.record_event` | `tests/unit/test_audit.py` (`test_audit_multiprocess_concurrency`, `test_audit_trail_concurrency_force_reload`) | **PARTIALLY-SUPPORTED-LIMITATION** | POSIX `fcntl.flock` synchronizes local process concurrency. `os.fsync` flushes OS page cache to storage controller, but physical persistence depends on disk hardware / write-cache policies. |
| **2.1 Tail Truncation Detection Boundary** | Internal hash chain verifies consistency from Genesis to last entry; detecting tail truncation requires external trust anchors. | `docs/audit_guarantees.md` : Section 2.1 | N/A (Threat Model Boundary) | **VERIFIED-BY-INSPECTION** | Explicitly documented limitation. Internal hash chains cannot detect trailing truncation without external WORM or ledger anchors. |
| **2.2 Proof of Truth Boundary** | Hash chain proves sequence integrity of logged events, but NOT external reality or unlogged out-of-band events. | `docs/audit_guarantees.md` : Section 2.2 | N/A (Threat Model Boundary) | **VERIFIED-BY-INSPECTION** | Formally documented security boundary. |
| **3.2 Nested Resource Extraction Mechanics** | `_extract_action_details()` parses nested dictionaries (`action.endpoint`) and object attributes consistently. | `epistemicos/gates.py` : `PermissionGate._extract_action_details` | `tests/unit/test_permission_gate_regression.py` (`test_permission_gate_nested_endpoint_extraction_allowed`) | **VERIFIED-BY-UNIT-TEST** | Resolves false-positive denials on nested API action structures. |
| **3.2 Scope Matching Consistency** | Extracted resource identifier is evaluated consistently across contract checking and trusted scope matching. | `epistemicos/gates.py` : `PermissionGate._validate_actions` | `tests/unit/test_permission_gate_regression.py` (`test_permission_gate_equivalent_representations_consistency`) | **VERIFIED-BY-UNIT-TEST** | Verified top-level dicts, nested dicts, and object wrappers match identical scope rules. |
| **4 Phase 2 Egress & Side-Effect Controls** | Default-deny network egress policy, IP pinning, URL normalization, and typed human approvals. | `epistemicos/containment.py`, `epistemicos/action_policy.py` | `tests/unit/test_phase2_egress_controls.py`, `tests/incident_lab/scenarios/case3_egress.py` | **VERIFIED-BY-SCENARIO-E2E** | Scenario tests verify egress blocking and HMAC-signed human approval verification. |

---

## 5. Precise Threat Model Qualifications & Boundaries

To ensure security claims are not overstated, the following cryptographic and operational boundaries are formally documented:

1. **Audit Chain Integrity vs. Privileged Host Compromise:**
   `TamperEvidentAuditTrail` provides tamper evidence against non-root application tampering via SHA-256 entry hash linking. However:
   - **Host File Permissions:** Protection relies on POSIX file permissions restricting write access to the audit log file path.
   - **HMAC Key Custody:** When HMAC mode is enabled (`EPISTEMICOS_AUDIT_HMAC_KEY`), security depends entirely on protecting the symmetric secret key from unauthorized access or extraction.
   - **Root / Privileged Host Access:** A compromised host with root access or write access to the log file and key store can modify historical entries and re-calculate valid hash chains from the point of modification onward. Detecting such modification requires external trust anchors (e.g. periodic hash checkpointing to permissioned ledgers or immutable WORM storage).

2. **Integrity vs. Completeness vs. Authenticity:**
   - **Integrity:** Proven for records written to the log (a broken link indicates modification or line deletion).
   - **Completeness:** Unproven. An attacker who bypasses logging calls prior to executing logic cannot be detected by the hash chain alone.
   - **Authenticity:** Provided via HMAC-SHA256 mode *only* relative to symmetric key holders (key holders can forge receipts; asymmetric non-repudiation requires PKI signatures).

3. **Storage Durability (`os.fsync`) Limits:**
   `TamperEvidentAuditTrail` executes `os.fsync(f.fileno())` after each record write. This flushes OS page caches to the storage controller interface. However, physical non-volatile persistence depends on the underlying filesystem (e.g. ext4, zfs), mount options, and physical drive controller write-cache flushing policies.

4. **Multi-Process Concurrency Scope:**
   Concurrency synchronization uses POSIX `fcntl.flock`. This serializes concurrent writes across processes on the same local OS instance. It does not synchronize file writes across distributed network filesystems (e.g. NFS) lacking lock support.

---

## 6. Test Report & Execution Evidence

### Execution Summary
- **Target SHA:** `14c5d22150fcbfe8a96d394560591f7de1dae505` (Base HEAD & PR HEAD)
- **Command:** `PYTHONPATH=/home/jules/.pyenv/versions/3.12.13/lib/python3.12/site-packages:. pytest`
- **Result:** `635 passed, 4 skipped in 25.55s`

### Accurate Skip Diagnostics
The 4 skipped tests were independently inspected to verify the exact reason for skipping:
1. `tests/unit/test_property_based.py:29` — Skipped because optional dependency `hypothesis` is not installed in the test environment (`No module named 'hypothesis'`).
2. `tests/unit/test_scheduler.py:10` — Skipped because optional ML dependency `torch` is not installed (`No module named 'torch'`).
3. `tests/unit/test_utils.py:7` — Skipped because optional ML dependency `transformers` is not installed (`No module named 'transformers'`).
4. `tests/unit/test_security_coverage_remediation.py:369` — Skipped because optional ML dependency `torch` is not installed (`No module named 'torch'`).

---

## 7. Reconciled Documentation Discrepancies & Follow-Up Actions

1. **Gate Sequence Discrepancy:**
   - **Documentation (`README.md`):** States `ShowerCurtainGate` $\rightarrow$ `EntropyGate` $\rightarrow$ `PermissionGate` $\rightarrow$ `TriangulationGate`.
   - **Runtime Code (`epistemicos/core.py`):** `ShowerCurtainEngine` acts as a pre-pipeline/transport layer, while `EpistemicOrchestrator` evaluates `PermissionGate` $\rightarrow$ `EntropyGate` $\rightarrow$ `TriangulationGate`.
   - **Follow-up Action Required:** Update `README.md` in a separate documentation revision PR to correctly document the runtime orchestrator pipeline gate order.

2. **Pseudonymization Function Terminology Discrepancy:**
   - **Documentation (`README.md`):** Uses the conceptual phrase "session pseudonyms" and "pseudonymize".
   - **Runtime Code (`epistemicos/shower_curtain/vault.py`):** Implemented via `LocalMappingVault.get_or_create_pseudonym()`.
   - **Follow-up Action Required:** Update `README.md` function references in a follow-up PR to explicitly name `LocalMappingVault.get_or_create_pseudonym()`.

---

## 8. Remaining Verification Gaps & Merge Recommendation

### Remaining Verification Gaps
- **Optional ML/GPU Dependencies:** Property-based tests using `hypothesis` and model integration tests requiring `torch` and `transformers` were skipped due to environment packaging choices.

### Final Recommendation
**DO NOT MERGE** (PR #273) in its current state until a follow-up PR updates `README.md` to align the documented gate sequence with the actual runtime pipeline implementation in `epistemicos/core.py`.
