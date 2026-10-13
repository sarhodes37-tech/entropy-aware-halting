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

### 1.2 Canonical Serialization Rules
All cryptographic hash and signature calculations adhere to explicit serialization rules:
- Dictionaries are lexicographically sorted by key (`sort_keys=True`).
- Non-finite numbers (`NaN`, `Infinity`) and un-serializable objects are rejected or sanitized prior to hashing.
- UTF-8 string encoding is strictly enforced.

### 1.3 Automatic PII, Prompt, and Credential Redaction
To prevent sensitive data leakage into immutable audit logs or receipts:
- Recursive sanitization (`_sanitize_sensitive_data`) automatically inspects all payload snippets, metadata, actions, rollbacks, and receipt details.
- Sensitive key matches (including `api_key`, `token`, `password`, `secret`, `ssn`, `banking_routing`, `account_number`, `account_balance_usd`, `proprietary_cargo`, `credit_card`, and `private_key`) are masked with `[REDACTED]` prior to hash generation and log writing.

### 1.4 Independent Out-of-Band Verifiability
- Receipts signed via SHA-256 or HMAC-SHA256 (`signing_key`) can be independently validated by any third-party verifier using `ReceiptGenerator.verify_receipt(receipt, signing_key=None)`.
- Verifiers do not need access to original orchestrator instances, volatile memory state, or internal database connections.

### 1.5 Hash Chain & Reordering Integrity
The `TamperEvidentAuditTrail` implements an append-only JSON-Lines log cryptographically chained from `GENESIS_SEED` (`EPISTEMIC_OS_GENESIS_BLOCK`):
$$\text{entry\_hash}_i = \text{SHA-256}(\text{prev\_hash}_i \mathbin{\Vert} \text{canonical\_json}(\text{entry}_i))$$
- **Missing Intermediate Events**: If an entry in the middle of the log is deleted, the `prev_hash` link of subsequent entries will break, failing `verify_chain_integrity()`.
- **Reordered Events**: Swapping the position of log entries invalidates both the hash chain links and the computed entry hashes.
- **Tampered Payloads**: Modifying any key or value within a historical log line causes a hash mismatch upon verification.
- **Duplicate & Replayed Events**: Duplicate `event_id` occurrences are explicitly tracked and rejected during chain verification.
- **Partial Writes**: Truncated or corrupted JSON lines caused by unexpected process interrupts are caught as `JSONDecodeError` on verification.

### 1.6 Concurrency & Process Restart Synchronization
- File-level exclusive locking (`fcntl.flock` on supported platforms) coordinates concurrent writers.
- Tail hash reads force a reload from disk under lock, eliminating in-memory cache staleness across process restarts or multi-process execution.

---

## 2. Properties Requiring External Trust Anchors or Durable Storage

While the internal hash chain and receipt system provide strong integrity guarantees against local tampering, certain security properties **cannot** be guaranteed solely by a local log file or in-memory generator:

### 2.1 Tail Truncation Detection Requires External Anchors
- **Boundary**: Internal hash chain validation verifies consistency from the Genesis block up to the last line present in the log file. If an attacker truncates trailing records from the end of the file, all remaining prior entries remain internally valid from Genesis to the truncated line.
- **Requirement**: Detecting tail truncation requires an **external trust anchor**. Anchor entry hashes or receipt signatures to an external immutable ledger (e.g., `TransactionalComplianceBroker` / `ImmutableLedgerAdapter`), WORM (Write Once Read Many) storage, or public time-stamping service.

### 2.2 Proof of Truth or Completeness Boundary
> **Important Security Principle**: **A hash chain is NOT proof of truth or completeness.**
- A hash chain only proves structural consistency, chronological immutability, and sequence integrity of records *that were actually written to it*.
- A hash chain **cannot** prove that:
  1. An out-of-band external event occurred or did not occur.
  2. An attacker or malicious process did not suppress logging calls prior to executing unauthorized logic.
  3. The raw input data supplied by an unauthenticated client reflects objective physical reality.

### 2.3 Multi-Host Distributed Consensus
- Local file locking (`fcntl.flock`) operates on a single OS kernel. Multi-host distributed environments require external consensus mechanisms (e.g., Raft, Paxos, or permissioned blockchain ledgers) to guarantee linearizable global transaction ordering across distinct network nodes.
