# EpistemicOS Tamper-Evident Audit Trail & Receipt System Guarantees

This document specifies the precise cryptographic properties, security boundaries, schema enforcement rules, corruption rejection policies, and trust requirements of the EpistemicOS `TamperEvidentAuditTrail`, `ReceiptGenerator`, and `TransactionalComplianceBroker`.

---

## 1. Guarantees Provided by Implementation

### 1.1 Strict Receipt Data Binding & Schema Enforcement
Receipts minted by `ReceiptGenerator.mint_receipt()` explicitly bind the following components into a unified canonical structure:
- **Transaction & Status**: Unique transaction identifier and final outcome (`COMMITTED` vs. `ROLLED_BACK`).
- **Gate Version & Pipeline Configuration**: Governance gate version tags and sanitized execution pipeline configuration dictionaries.
- **Exact Input Binding**: A SHA-256 hash (`input_hash`) computed over the canonical JSON representation of the sanitized input data.
- **Decision & Outcome Context**: Fine-grained decision rationale (`decision_details`), execution outcomes (`execution_outcome`), and confidence matrices (`confidence_matrix`).
- **Event Log Trace**: Ordered sequence of intermediate pipeline events (`ActionProposed`, `RollbackIssued`), each tagged with monotonic sequence indices (`idx`) and UTC ISO 8601 timestamps.
- **Signature Algorithm Tag**: Explicit `"signature_algorithm"` field (`"HMAC-SHA256"` or `"SHA256"`).

#### Fail-Closed Schema Validation
`ReceiptGenerator.verify_receipt(receipt, signing_key=None)` enforces strict schema validation:
- **Required Fields**: `transaction_id`, `status`, `gate_version`, `config`, `confidence_matrix`, `event_log`, `signature_algorithm`, and `signature` must all be present.
- **Unknown Field Rejection**: Inserting any unknown key outside the allowed schema causes immediate verification failure (`return False`).
- **Null Substitution & Type Enforcement**: Null values for required fields or invalid types (e.g. non-string transaction IDs, non-dictionary configurations, invalid status strings) are rejected.
- **Signature Format Validation**: Signatures must be valid 64-character hexadecimal strings.

### 1.2 Canonical Serialization & Non-Native Values (Sets/Frozensets)
All cryptographic hash and signature calculations adhere to explicit canonical serialization rules:
- Dictionaries are lexicographically sorted by key (`sort_keys=True`).
- Non-JSON-native structures like `set` and `frozenset` are deterministically converted into sorted lists (`sorted(...)`) before JSON serialization, preventing non-deterministic key/value order across Python runtimes.
- UTF-8 string encoding is strictly enforced (`encode("utf-8")`).
- `receipt_bytes` is computed over the entire canonical JSON dictionary excluding the `"signature"` field itself.

### 1.3 Cryptographic Signature Modes & Algorithm Downgrade Protection
- **SHA-256 Mode (Digest Checksum)**: When no `signing_key` is supplied, `mint_receipt` records `"signature_algorithm": "SHA256"` and computes an unauthenticated SHA-256 digest over `receipt_bytes`.
  *Security Boundary*: Plain SHA-256 provides integrity **only** relative to a pre-shared or externally anchored digest. It does not provide origin authentication.
- **HMAC-SHA256 Mode (Symmetric Authentication)**: When a secret `signing_key` is supplied, `mint_receipt` records `"signature_algorithm": "HMAC-SHA256"` and computes `hmac.new(key, receipt_bytes, hashlib.sha256)`.
  *Security Boundary*: HMAC provides symmetric origin authentication. Third-party verifiers must hold the symmetric secret key to verify the HMAC signature. Because key-holders can also forge receipts, HMAC provides symmetric authentication rather than asymmetric non-repudiation.
- **Algorithm Downgrade & Confusion Protection**: `ReceiptGenerator.verify_receipt(receipt, signing_key)` enforces strict algorithm matching:
  - If a `signing_key` is provided to `verify_receipt`, the receipt **must** specify `"signature_algorithm": "HMAC-SHA256"`.
  - If no `signing_key` is provided to `verify_receipt`, the receipt **must** specify `"signature_algorithm": "SHA256"`.
  - Unknown algorithms (e.g., `"MD5"`, `"NONE"`, `"RSA"`) or algorithm mismatches result in immediate verification failure.

### 1.4 Automatic PII, Prompt, and Credential Redaction
- Recursive sanitization (`_sanitize_sensitive_data`) inspects all payload snippets, metadata, actions, rollbacks, sets, frozensets, tuples, and receipt details.
- Key name matching redacts keys containing sensitive terms (`api_key`, `token`, `password`, `secret`, `ssn`, `banking_routing`, `account_number`, `account_balance_usd`, `proprietary_cargo`, `credit_card`, `private_key`, `bearer`, `auth`, `credential`, `x-api-key`).
- Free-text regex scanning redacts Bearer tokens (`Bearer \S+`), API keys (`sk-[a-zA-Z0-9_\-]+`), and inline credential assignments (`password=\S+`, `api_key=\S+`).
- **Redaction Collision Trade-Off**: Computing `input_hash` on sanitized input preserves privacy in persistent receipts/logs. However, inputs that differ *solely* in their redacted secret values will yield identical sanitized representations and identical `input_hash` values.

### 1.5 Crash Safety & Explicit Corruption Rejection Policy
The `TamperEvidentAuditTrail` implements an append-only JSON-Lines log cryptographically chained from `GENESIS_SEED` (`EPISTEMIC_OS_GENESIS_BLOCK`):
$$\text{entry\_hash}_i = \text{SHA-256}(\text{prev\_hash}_i \mathbin{\Vert} \text{canonical\_json}(\text{entry}_i))$$
- **Health Inspection Separation**: `TamperEvidentAuditTrail.inspect_log_health()` separates log health status (`is_healthy: bool`) from retrieving the last valid entry hash (`last_valid_hash: str`).
- **Corruption Rejection Policy**: `record_event()` calls `inspect_log_health()` under file lock (`fcntl.flock`). If the audit log contains a corrupted tail, unlinked records, or tampered lines, `record_event()` **refuses to write** and raises a `RuntimeError("Cannot write to audit trail: Log corruption detected...")`. Historical evidence is never silently overwritten or appended to after a damaged tail.
- **Missing Intermediate Events & Reordering**: Deleting or swapping log lines invalidates subsequent `prev_hash` links and triggers chain failure.
- **Duplicate & Replayed Events**: Duplicate `event_id` occurrences are explicitly tracked and rejected by `verify_chain_integrity()` and `inspect_log_health()`.

### 1.6 Concurrency & OS Durability
- Multi-process concurrency is synchronized using exclusive file locks (`fcntl.flock` on POSIX systems).
- `force_reload=True` forces re-reading the tail hash from disk while holding the file lock, preventing chain forks across concurrent processes.
- `os.fsync(f.fileno())` flushes OS page caches to physical storage after writing each record.

---

## 2. Properties Requiring External Trust Anchors or Durable Storage

### 2.1 Tail Truncation Detection Requires External Anchors
- **Boundary**: Internal hash chain validation verifies consistency from Genesis up to the last line present in the log file. If an attacker truncates trailing records from the end of the file, all remaining prior entries remain internally valid from Genesis to the truncated line.
- **Requirement**: Detecting tail truncation requires an **external trust anchor**, such as periodically checkpointing block hashes/receipts to an immutable permissioned ledger (`TransactionalComplianceBroker` / `ImmutableLedgerAdapter`), WORM storage, or public time-stamping service.

### 2.2 Proof of Truth or Completeness Boundary
> **Important Security Principle**: **A hash chain is NOT proof of truth or completeness.**
- A hash chain only proves structural consistency, chronological immutability, and sequence integrity of records *that were actually written to it*.
- A hash chain **cannot** prove that:
  1. An out-of-band external event occurred or did not occur.
  2. An attacker or malicious process did not suppress logging calls prior to executing unauthorized logic.
  3. The raw input data supplied by an unauthenticated client reflects objective physical reality.

### 2.3 Asymmetric Non-Repudiation
- True non-repudiation without key-holder collusion risk requires asymmetric digital signatures (e.g. RSA/ECDSA/Ed25519) and a Public Key Infrastructure (PKI) or Key Management System (KMS).

---

## 3. Authorization Scope & Nested Resource Extraction Mechanics

### 3.1 Defect Analysis & Root Cause
Prior to the refinement in `epistemicos/gates.py`:
- `PermissionGate._extract_action_details()` extracted operation and resource identifiers from top-level dictionary keys (`op`, `operation`, `action`, `node`, `target`, `resource`).
- When action payloads contained nested action objects (e.g., `{"action": {"op": "api_call", "endpoint": "/issue_binder"}}`), `_extract_action_details()` extracted the top-level `op` value from the nested dictionary but failed to inspect the nested `"endpoint"` field for the resource target.
- Valid requests containing nested `"endpoint"` attributes failed the mandatory resource check ("Missing or invalid target/resource identifier in proposed action") and were incorrectly halted as unauthorized.

### 3.2 Implementation & Code Paths
The refinement in `PermissionGate` was applied to two key methods in `epistemicos/gates.py`:
1. **`_extract_action_details(act)`:** Extended resource field lookup to inspect `endpoint`, `node`, `policy`, `resource`, and `target` inside nested dictionary structures (`act.get("action")`) and object attributes (`getattr(act, "action")`).
2. **`_validate_actions(trusted_scope, proposed_actions, t0)`:** Unified scope matching logic to ensure resource validation against `allowed_resources` uses the exact same extracted resource string (`node_val`) across both contract evaluation and scope checks.

### 3.3 Regression Test Matrix
The behavior is verified in `tests/unit/test_permission_gate_regression.py`:
- `test_permission_gate_nested_endpoint_extraction_allowed`: Asserts that nested `{"action": {"op": "api_call", "endpoint": "/issue_binder"}}` is correctly extracted and allowed.
- `test_permission_gate_nested_endpoint_execution_reached`: Asserts that an authorized nested endpoint request reaches the orchestrator's execution callback.
- `test_permission_gate_unauthorized_endpoint_denied`: Confirms that unauthorized nested endpoints remain strictly blocked (`HALT`).
- `test_permission_gate_missing_malformed_structures_fail_closed`: Verifies that truly missing or empty operation/resource fields fail closed without false passes.
- `test_permission_gate_equivalent_representations_consistency`: Ensures top-level dicts, nested dicts, and custom object wrappers evaluate consistently.
