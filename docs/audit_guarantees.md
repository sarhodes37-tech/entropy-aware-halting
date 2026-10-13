# EpistemicOS Tamper-Evident Audit Trail & Receipt System Guarantees

This document specifies the precise cryptographic properties, security boundaries, and trust requirements of the EpistemicOS `TamperEvidentAuditTrail`, `ReceiptGenerator`, and `TransactionalComplianceBroker`.

---

## 1. Guarantees Provided by Implementation

### 1.1 Strict Receipt Data Binding
Receipts minted by `ReceiptGenerator.mint_receipt()` explicitly bind the following components into a unified canonical structure:
- **Transaction & Status**: Unique transaction identifier and final outcome (`COMMITTED` vs. `ROLLED_BACK`).
- **Gate Version & Pipeline Configuration**: Governance gate version tags and sanitized execution pipeline configuration dictionaries.
- **Exact Input Binding**: A SHA-256 hash (`input_hash`) computed over the canonical JSON representation of the sanitized input data.
- **Decision & Outcome Context**: Fine-grained decision rationale (`decision_details`), execution outcomes (`execution_outcome`), and confidence matrices (`confidence_matrix`).
- **Event Log Trace**: Ordered sequence of intermediate pipeline events (`ActionProposed`, `RollbackIssued`), each tagged with monotonic sequence indices (`idx`) and UTC ISO 8601 timestamps.
- **Signature Algorithm Tag**: Explicit `"signature_algorithm"` field (`"HMAC-SHA256"` or `"SHA256"`).

### 1.2 Canonical Serialization Rules & Field Hashing
All cryptographic hash and signature calculations adhere to explicit canonical serialization rules:
- Dictionaries are lexicographically sorted by key (`sort_keys=True`).
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
  - Any attempt to manipulate `signature_algorithm` or omit keys results in immediate verification failure.

### 1.4 Automatic PII, Prompt, and Credential Redaction
- Recursive sanitization (`_sanitize_sensitive_data`) inspects all payload snippets, metadata, actions, rollbacks, sets, frozensets, tuples, and receipt details.
- Key name matching redacts keys containing sensitive terms (`api_key`, `token`, `password`, `secret`, `ssn`, `banking_routing`, `account_number`, `account_balance_usd`, `proprietary_cargo`, `credit_card`, `private_key`, `bearer`, `auth`, `credential`, `x-api-key`).
- Free-text regex scanning redacts Bearer tokens (`Bearer \S+`), API keys (`sk-[a-zA-Z0-9_\-]+`), and inline credential assignments (`password=\S+`, `api_key=\S+`).
- **Redaction Collision Trade-Off**: Computing `input_hash` on sanitized input preserves privacy in persistent receipts/logs. However, inputs that differ *solely* in their redacted secret values will yield identical sanitized representations and identical `input_hash` values.

### 1.5 Hash Chain & Reordering Integrity
The `TamperEvidentAuditTrail` implements an append-only JSON-Lines log cryptographically chained from `GENESIS_SEED` (`EPISTEMIC_OS_GENESIS_BLOCK`):
$$\text{entry\_hash}_i = \text{SHA-256}(\text{prev\_hash}_i \mathbin{\Vert} \text{canonical\_json}(\text{entry}_i))$$
- **Missing Intermediate Events**: Deleting an entry breaks subsequent `prev_hash` links, failing `verify_chain_integrity()`.
- **Reordered Events**: Swapping entry order invalidates both link hashes and computed entry hashes.
- **Tampered Payloads**: Modifying historical log line values causes a hash mismatch.
- **Duplicate & Replayed Events**: Duplicate `event_id` occurrences are explicitly tracked and rejected by `verify_chain_integrity()`.
- **Partial Writes & Crash Safety**: `verify_chain_integrity()` flags `Malformed JSON` on truncated lines. During log appends, `_get_last_hash` scans backwards past incomplete line fragments caused by mid-write process crashes to recover the last valid entry hash, preventing chain resets to Genesis.

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
