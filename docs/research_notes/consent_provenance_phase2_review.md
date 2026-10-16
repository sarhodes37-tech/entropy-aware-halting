# EpistemicOS Research Report: Consent Provenance & External Policy Drift — Phase 2 Design Review

**Author:** EpistemicOS Security Architecture & Audit Team
**Date:** October 2026
**Document Version:** `2.0.0`
**Target Module Area:** `epistemicos/gates.py`, `epistemicos/provenance.py`, `epistemicos/audit.py`, `epistemicos/compliance.py`, `epistemicos/core.py`
**Status:** NON-MUTATING ADVERSARIAL DESIGN REVIEW & VULNERABILITY AUDIT

---

## Executive Summary

This Phase 2 design review performs an adversarial, repository-grounded audit of the initial Consent Provenance and Policy Drift proposal (`docs/research_notes/consent_provenance_and_policy_drift.md`).

While the Phase 1 report outlined a useful conceptual gate concept, a line-by-line inspection of the actual codebase reveals that the proposed design **failed to substantiate several key security guarantees**. Specifically, the proposed design suffered from critical design defects including unauthenticated evidence injection, lack of cryptographic binding between records and policy hashes, default-ALLOW fallbacks on missing baseline policies, inability to classify semantic policy ambiguities, and susceptibility to TOCTOU races in gate evaluation.

This report provides:
1. **Line-by-line code citations** for all reusable EpistemicOS abstractions, explicitly distinguishing existing verified behavior from proposed claims.
2. **Detailed attack traces, code paths, invariants, and falsifiable tests** for 12 distinct adversarial vulnerability scenarios.
3. **Formal separation of trust domains**, defining an untrusted-to-authenticated observation pipeline and isolating legal enforceability as an external human/institutional decision.
4. **Enforceable system invariants** and explicit identification of current architectural limitations.
5. **A deterministic evaluation plan** with positive/negative controls and realistic measurement protocols.
6. **A prioritized findings table** and an explicit **CONDITIONAL GO / NO-GO RECOMMENDATION**.

---

## 1. Verification of Repository Implementation Claims

To establish an authoritative baseline, every reusable abstraction cited in Phase 1 is verified against the actual repository codebase (`epistemicos/`).

### 1.1 Gate Base Interfaces & Data Structures (`epistemicos/gates.py`)
- **`ControlPlaneGate`** (`epistemicos/gates.py`, lines 169–218):
  - *Existing Verified Behavior:* Defines `evaluate_contract(gate_input: GateInput) -> GateOutcome`. Implements `evaluate_safe(gate_input)` which catches unhandled exceptions and fails closed (`GateDecision.HALT`) if `config.is_critical` is `True`. Implements `evaluate(payload, context)` as an adapter converting `GateOutcome` to `GateResult`.
  - *Proposed Claim vs Reality:* Verified. `ControlPlaneGate` is fully implemented and active in existing tests.
- **`GateInput`** (`epistemicos/gates.py`, lines 37–43):
  - *Existing Verified Behavior:* Holds `payload: Dict[str, Any]`, `context: Dict[str, Any]`, `operation_id`, `requestor_id`, and `attempt_number`.
  - *Proposed Claim vs Reality:* Verified.
- **`GateOutcome`** (`epistemicos/gates.py`, lines 56–105):
  - *Existing Verified Behavior:* Typed outcome dataclass containing `decision: GateDecision`, `reason_code: str`, `gate_name: str`, `gate_version: str`, `evidence: Dict[str, Any]`, `latency_ms: float`. Property `passed` returns `True` strictly when `decision == GateDecision.ALLOW`. `to_gate_result()` maps `ALLOW` to `GateAction.ALLOW` ("ALLOWED") and any non-ALLOW decision (`DENY`, `HALT`, `INDETERMINATE`) to `GateAction.HALT` ("HALTED").
  - *Proposed Claim vs Reality:* Verified.
- **`GateDecision`** (`epistemicos/gates.py`, lines 29–34):
  - *Existing Verified Behavior:* Enum defining `ALLOW`, `DENY`, `HALT`, `INDETERMINATE`.
  - *Proposed Claim vs Reality:* Verified.

### 1.2 Gate Composition & Pipeline Orchestration (`epistemicos/core.py`)
- **`EpistemicOrchestrator`** (`epistemicos/core.py`, lines 24–240):
  - *Existing Verified Behavior:* Manages gate list `self.gates` (lines 62–66). In `_evaluate_gates()` (lines 173–190), iterates through `self.gates`, calling `gate.evaluate(payload_dump, context)`. Catches unhandled exceptions to return a fail-closed `GateResult(action=GateAction.HALT)`. If any gate returns `action != GateAction.ALLOW` or `passed == False`, execution halts immediately.
  - *Crucial Finding:* `EpistemicOrchestrator` passes unauthenticated `context` directly to gates. It does **not** sanitize or authenticate `context` before calling gates.

### 1.3 Execution Provenance Subsystem (`epistemicos/provenance.py`)
- **`TrustedExecutionBoundary`** (`epistemicos/provenance.py`, lines 212–332):
  - *Existing Verified Behavior:* Manages atomic consumption of single-use `authorization_token_id` in `execute_protected_action()` (lines 268–282) using `self._lock` (`threading.Lock`). Validates that `current_digest` computed from request payload matches `authorized_digest`. Emits `EXECUTION_STARTED`, `EXECUTION_SUCCEEDED`, or `EXECUTION_FAILED` events directly to `LocalProvenanceStore`.
  - *Crucial Finding:* `TrustedExecutionBoundary` enforces atomic token consumption and payload digest matching **only if** actions are routed through `execute_protected_action()`. Direct tool calls by agents that bypass this method do not trigger token checks.
- **`LocalProvenanceStore`** (`epistemicos/provenance.py`, lines 80–209):
  - *Existing Verified Behavior:* Append-only JSON-Lines store using `_inspect_health()` (lines 135–179) to verify SHA-256 hash chains (`prev_hash` to `entry_hash`) and enforce file locking (`fcntl.flock`).
  - *Crucial Finding:* As documented in lines 82–83, local process file locks do not constitute an independent trust boundary against a host-level or root process compromise.
- **`ProvenanceReconciler`** (`epistemicos/provenance.py`, lines 343–438):
  - *Existing Verified Behavior:* Cross-validates `ACTION_PROPOSED`, `AUTHORIZATION_GRANTED`, and `EXECUTION_SUCCEEDED` events for a given `correlation_id`. Detects unauthorized execution, target mismatches, digest shifts, and false agent claims.

### 1.4 Audit Trail & Receipt Generation (`epistemicos/audit.py`)
- **`TamperEvidentAuditTrail`** (`epistemicos/audit.py`, lines 94–226):
  - *Existing Verified Behavior:* Append-only, SHA-256 chained audit logger. Uses `_sanitize_sensitive_data()` (lines 40–62) to redact PII, Bearer tokens, and keys.
- **`ReceiptGenerator`** (`epistemicos/audit.py`, lines 229–336):
  - *Existing Verified Behavior:* Mints signed receipts (`HMAC-SHA256` or `SHA256`). `verify_receipt()` (lines 280–336) enforces strict schema checking, hex format validation, algorithm matching, and constant-time signature comparison (`hmac.compare_digest`).

### 1.5 Off-Chain Compliance & Ledger Anchoring (`epistemicos/compliance.py`)
- **`TransactionalComplianceBroker`** (`epistemicos/compliance.py`, lines 62–148):
  - *Existing Verified Behavior:* Manages mutable off-chain PII storage (`OffChainStoreAdapter`) and immutable ledger block commitment (`ImmutableLedgerAdapter`). `execute_right_to_be_forgotten()` enforces `requestor_id` authorization checks and uses safe file-descriptor handling (`os.open(..., os.O_RDWR | os.O_NOFOLLOW)`) to prevent TOCTOU symlink traversal.

---

## 2. Adversarial Design Review (12 Vulnerability Scenarios)

An adversarial analysis of the Phase 1 proposed design reveals 12 specific vulnerability scenarios. Each scenario is documented with its attack trace, root-cause code path, expected security invariant, and falsifiable test.

### Vulnerability 1: Forged Authorization Records or Policy Snapshots
- **Attack Trace:** An untrusted caller injects a forged `VersionedAuthorizationRecord` directly into `context["authorization_record"]` inside the unauthenticated request dictionary passed to `EpistemicOrchestrator.process_submission(raw_payload, context)`. Because the gate reads `context.get("authorization_record")` without verifying a cryptographic signature or querying a trusted store, the gate accepts the forged record.
- **Code Path:** Proposed `ConsentAndPolicyDriftGate.evaluate_contract()` lines: `auth_record = context.get("authorization_record")`.
- **Expected Invariant:** Authorization records and policy snapshots MUST be authenticated via cryptographic signatures verified against a trusted key store or fetched directly from a process-isolated, trusted record store.
- **Falsifiable Test:** Submit a request with a synthetically constructed `VersionedAuthorizationRecord` containing `principal_id="admin"` and valid purpose grants, but with an invalid or missing signature. Assert that the gate returns `GateDecision.HALT` with reason `UNAUTHENTICATED_AUTHORIZATION_RECORD`.

### Vulnerability 2: Substitution of Baseline Policy Inconsistent with Bound Digest
- **Attack Trace:** An attacker provides a valid, signed `VersionedAuthorizationRecord` bound to `bound_policy_digest = "hash_A"`. However, in `context["baseline_policy_snapshot"]`, the attacker supplies a modified policy snapshot whose `raw_document_hash` is `"hash_B"`. The proposed gate compares `baseline_policy_snapshot` against `active_policy_snapshot` without asserting that `baseline_policy_snapshot.raw_document_hash == auth_record.bound_policy_digest`.
- **Code Path:** Proposed gate code directly executed `self.diff_engine.compare(baseline_policy, active_policy)` without checking `auth_record.bound_policy_digest`.
- **Expected Invariant:** The baseline policy snapshot used for drift comparison MUST match `VersionedAuthorizationRecord.bound_policy_digest` exactly.
- **Falsifiable Test:** Pass `auth_record.bound_policy_digest = "sha256_AAA"` and a `baseline_policy_snapshot` with `raw_document_hash = "sha256_BBB"`. Assert the gate returns `GateDecision.HALT` with reason `BASELINE_POLICY_DIGEST_MISMATCH`.

### Vulnerability 3: Missing Baseline or Active Policy Evidence Silently Resulting in ALLOW
- **Attack Trace:** An attacker submits a request without providing `active_policy_snapshot` or `baseline_policy_snapshot` in `context`. The proposed gate evaluated `if active_policy and baseline_policy:` block; when either was `None`, it skipped drift analysis entirely and fell through to returning `GateDecision.ALLOW`.
- **Code Path:** Proposed `ConsentAndPolicyDriftGate.evaluate_contract()` step 4: `if active_policy and baseline_policy:` fell through to `return GateOutcome(decision=GateDecision.ALLOW)`.
- **Expected Invariant:** Missing required policy evidence MUST fail closed (`GateDecision.HALT` or `GateDecision.DENY`) whenever the authorization record requires policy drift validation.
- **Falsifiable Test:** Submit a valid `VersionedAuthorizationRecord` with `review_conditions={"require_active_policy_snapshot": True}` but pass `active_policy_snapshot = None` in context. Assert outcome is `GateDecision.HALT`.

### Vulnerability 4: Material Policy Changes Unlabeled as Expansions
- **Attack Trace:** Vendor modifies terms from *"We do not share data with third parties"* to *"We may share anonymized data with strategic partners"*. The proposed `PolicyDiffEngine` performed key-based comparison on `parsed_clauses`. If the parser generated a modified key without setting `expanded_scope=True` or `grants_data_use=True`, the diff engine classified the severity as `RESTRICTION_ADDED` instead of `EXPANSION_MATERIAL`, resulting in `ALLOW` instead of `HALT`.
- **Code Path:** Proposed `PolicyDiffEngine.compare()` severity logic: `severity = PolicyChangeSeverity.EXPANSION_MATERIAL if expanded_purposes else ...`
- **Expected Invariant:** Any modification or addition to clauses governing data sharing, purpose grants, or content indexing MUST be classified as a material expansion by default unless explicitly verified as restrictive by a trusted authority.
- **Falsifiable Test:** Supply a baseline policy clause `sharing: prohibited` and active policy clause `sharing: allowed_for_partners`. Assert `PolicyDiffEngine` marks `severity = EXPANSION_MATERIAL` and `is_material = True`.

### Vulnerability 5: Unclassifiable Changes Failing to Yield AMBIGUOUS Classification
- **Attack Trace:** Vendor terms introduce a complex, non-standard conditional clause (e.g., *"Data may be used subject to Section 4.2 b unless opted out via form X"*). The proposed `PolicyDiffEngine` performed simple dictionary equality (`baseline_clauses[k] != v`). It had no logic to return `PolicyChangeSeverity.AMBIGUOUS`, so every modified string key was treated as a deterministic material change or restriction.
- **Code Path:** Proposed `PolicyDiffEngine` contained `PolicyChangeSeverity.AMBIGUOUS` in the enum definition but had zero code paths inside `compare()` that ever produced `AMBIGUOUS`.
- **Expected Invariant:** If clause parser confidence is below threshold ($<0.90$) or clause semantics contain unparseable conditional logic, `PolicyDiffEngine` MUST assign `severity = AMBIGUOUS`, triggering `GateDecision.INDETERMINATE`.
- **Falsifiable Test:** Input a clause dict containing `{"text": "...", "parser_confidence": 0.40}`. Assert `PolicyDiffEngine` returns `severity = AMBIGUOUS` and gate returns `GateDecision.INDETERMINATE`.

### Vulnerability 6: Scope Constraints Ignored in Authorization Record
- **Attack Trace:** A `VersionedAuthorizationRecord` specifies `resource_selector = "corpus_news/*"` and `authorized_recipients = ["agent_alpha"]`. An agent submits an action targeting `"database_finance/users"` for recipient `"agent_beta"`. The proposed gate checked only `requested_purpose` against `authorized_purposes`, completely ignoring `resource_selector` and `authorized_recipients`.
- **Code Path:** Proposed `ConsentAndPolicyDriftGate.evaluate_contract()` contained logic for step 3 (`requested_purpose`) but lacked validation loops for `resource_selector` or `authorized_recipients`.
- **Expected Invariant:** Gate evaluation MUST validate all 6 principal constraints: action, resource, purpose, recipient, effective date, and policy digest.
- **Falsifiable Test:** Submit `resource_selector = "news/*"` and proposed action target `"finance/db"`. Assert gate returns `GateDecision.DENY` with reason `RESOURCE_OUTSIDE_AUTHORIZATION_SCOPE`.

### Vulnerability 7: Agent-Controlled Purpose Declarations Overriding Metadata
- **Attack Trace:** An adversarial prompt injects `"purpose": "search_indexing"` into the payload JSON, while the actual executable action is `train_model(dataset)`. The gate evaluated `requested_purpose = context.get("requested_purpose") or payload.get("purpose")`. The untrusted agent payload controlled the purpose string, overriding actual action semantics.
- **Code Path:** `requested_purpose = context.get("requested_purpose") or payload.get("purpose")`.
- **Expected Invariant:** Action purpose and target MUST be derived from trusted execution context or pre-registered action metadata, never from unauthenticated agent payload strings.
- **Falsifiable Test:** Pass `payload={"purpose": "authorized_indexing"}` and `context={"actual_executable": train_model_func, "trusted_action_metadata": {"purpose": "ai_model_training"}}`. Assert purpose is resolved as `"ai_model_training"` and denied.

### Vulnerability 8: Revocation Races and Stale Cached Authorization
- **Attack Trace:** Principal revokes consent in the central database. An agent continues executing multi-step reasoning trajectories using a cached `VersionedAuthorizationRecord` object stored in `context` across 10 steps. The gate reads the static in-memory object and approves all 10 steps.
- **Code Path:** Gate read `context.get("authorization_record")` from the request dict without querying a live revocation list digest or cache-invalidation epoch.
- **Expected Invariant:** Every gate evaluation MUST verify consent record freshness against a live, process-isolated revocation list or epoch version.
- **Falsifiable Test:** Revoke record `REC_001` in `RevocationRegistry`. Pass `authorization_record` for `REC_001` with `revoked=False` in context. Assert gate queries registry, detects revocation, and returns `GateDecision.DENY`.

### Vulnerability 9: Future-Effective Terms Enforced Prematurely or Accepted Early
- **Attack Trace:** Vendor publishes updated terms on Oct 1 with effective date Oct 15 (`effective_at = T_future`). On Oct 5 (`T_now`), vendor policy snapshot is submitted. The gate evaluates the new policy snapshot as currently active, either enforcing new restrictions 10 days early or granting expanded permissions 10 days before legal grant.
- **Code Path:** Proposed `PolicySnapshot` lacked an `effective_at` field and `PolicyDiffEngine` evaluated snapshots without comparing timestamps against current time $T_{\text{now}}$.
- **Expected Invariant:** Policy snapshots with `effective_at > T_now` MUST NOT override active baseline policies for current action authorization.
- **Falsifiable Test:** Submit `active_policy` with `effective_at = T_now + 86400`. Assert gate evaluates current authorization against baseline active terms and flags future terms as pending.

### Vulnerability 10: Receipt Replay and Action-Payload Substitution
- **Attack Trace:** An attacker captures a valid, signed decision receipt from `transaction_1` (`action: "read"`). The attacker submits a new request (`transaction_2`, `action: "delete"`) attaching the signed receipt from `transaction_1`. If the execution boundary accepts the receipt signature without checking `transaction_id` or `input_hash`, the unauthorized action executes.
- **Code Path:** In `epistemicos/audit.py`, `ReceiptGenerator.verify_receipt()` validates signature over receipt dict, but does not verify that `receipt["transaction_id"]` matches the current execution context `request_id` or that `receipt["input_hash"]` matches the active payload digest.
- **Expected Invariant:** Execution boundaries MUST assert that receipt `transaction_id`, `correlation_id`, and `input_hash` match the active execution request exactly before honoring prior decisions.
- **Falsifiable Test:** Submit receipt for `TX_100` (`input_hash: AAA`) to authorize `TX_200` (`input_hash: BBB`). Assert `TrustedExecutionBoundary` rejects request with `ValueError("Payload digest mismatch")`.

### Vulnerability 11: Protected Actions Bypassing Gate or Executing Post-DENY/HALT
- **Attack Trace:** An agent tool directly invokes a python function (e.g. `db.delete_records()`) without wrapping the call in `EpistemicOrchestrator.process_submission()` or `TrustedExecutionBoundary.execute_protected_action()`. Even if the gate returned `GateDecision.DENY`, the raw Python code executes because enforcement was not attached to the underlying method execution.
- **Code Path:** `EpistemicOrchestrator._evaluate_gates()` returns a `GateResult`. If caller code ignores `result["status"] == "HALTED"` and continues calling the tool, execution occurs.
- **Expected Invariant:** Protected state-mutating actions MUST be reachable ONLY through `TrustedExecutionBoundary`, which consumes single-use authorization tokens emitted strictly upon `GateDecision.ALLOW`.
- **Falsifiable Test:** Attempt to execute `execute_protected_action()` without a valid authorization token emitted by a gate `ALLOW` outcome. Assert `PermissionError` is raised.

### Vulnerability 12: Registration of Opt-In Gate Changing Behavior for Existing Workloads
- **Attack Trace:** `ConsentAndPolicyDriftGate` is appended to `EpistemicOrchestrator.gates`. Existing workloads that do not supply `authorization_record` in `context` suddenly fail with `GateDecision.HALT` (`MISSING_AUTHORIZATION_RECORD`), causing immediate regression across all production pipelines.
- **Code Path:** In `epistemicos/gates.py`, if a new gate is inserted into `EpistemicOrchestrator.gates` in `__init__`, every submission passes through it.
- **Expected Invariant:** Opt-in governance gates MUST operate in passthrough mode (`GateDecision.ALLOW`) or be completely bypassed unless explicitly enabled in `GateConfig` or context.
- **Falsifiable Test:** Process a standard `CanonicalProblemRepresentation` payload without consent context through `EpistemicOrchestrator`. Assert response is `ALLOWED` when `ConsentAndPolicyDriftGate` is configured as opt-in/disabled.

---

## 3. Prioritized Findings Table

| ID | Finding Title | Severity | Affected Component | Existing Code Reference | Root Cause / Impact |
|---|---|---|---|---|---|
| **F-01** | Unauthenticated Context Injection | **CRITICAL** | `EpistemicOrchestrator` / Gates | `epistemicos/core.py:173` | Untrusted caller can inject fake `authorization_record` or `baseline_policy` in `context` dict. |
| **F-02** | Direct Execution Bypass | **CRITICAL** | `TrustedExecutionBoundary` | `epistemicos/provenance.py:240` | Tools invoked directly bypass orchestrator gates and token validation entirely. |
| **F-03** | Missing Baseline Policy Check | **HIGH** | Proposed Gate | Proposed Phase 1 Spec | Gate compares active vs baseline policy without verifying baseline matches record's `bound_policy_digest`. |
| **F-04** | Default-ALLOW on Missing Evidence | **HIGH** | Proposed Gate | Proposed Phase 1 Spec | Missing active policy snapshot falls through to `ALLOW` instead of failing closed. |
| **F-05** | Agent Purpose Spoofing | **HIGH** | `PermissionGate` / Proposed Gate | `epistemicos/gates.py:320` | Purpose string read from untrusted `payload["purpose"]` rather than verified action metadata. |
| **F-06** | Incomplete Constraint Check | **MEDIUM** | Proposed Gate | Proposed Phase 1 Spec | Gate validates purpose but ignores `resource_selector` and `authorized_recipients`. |
| **F-07** | Stale Authorization Cache | **MEDIUM** | Proposed Gate | Proposed Phase 1 Spec | Reads static record object in context without checking live revocation registry. |
| **F-08** | Dead-Code Ambiguity Enum | **MEDIUM** | Proposed Diff Engine | Proposed Phase 1 Spec | `PolicyChangeSeverity.AMBIGUOUS` defined in enum but never emitted by diff logic. |
| **F-09** | Unbound Receipt Verification | **MEDIUM** | `ReceiptGenerator` | `epistemicos/audit.py:280` | `verify_receipt()` checks signature integrity but not active transaction or payload binding. |
| **F-10** | Un-Bypasable Default Gate Risk | **LOW** | `EpistemicOrchestrator` | `epistemicos/core.py:62` | Registering gate globally breaks existing workloads lacking consent metadata. |

---

## 4. Separation of Trust Domains

To prevent security ambiguity, system responsibilities are partitioned into 4 explicit trust domains. Software enforcement is strictly separated from legal adjudication.

```
+---------------------------------------------------------------------------------------------------+
|                                   TRUST DOMAIN SEPARATION                                         |
+---------------------------------------------------------------------------------------------------+
| DOMAIN 1: UNTRUSTED EXTERNAL ENVIRONMENT                                                          |
|   - External Websites, Vendor Terms Pages, Meta API, Agent LLM Prompts, Scraping Bots             |
|   - Raw documents, robots.txt, and vendor terms summaries are UNTRUSTED CLAIMS.                   |
+---------------------------------------------------------------------------------------------------+
                                                |
                                                | Observation Ingestion & Attestation
                                                v
+---------------------------------------------------------------------------------------------------+
| DOMAIN 2: TRUSTED OBSERVATION & EVIDENCE PIPELINE                                                 |
|   - PolicySnapshotIngestor, Cryptographic Key Store, ImmutableLedgerAdapter                       |
|   - Converts untrusted web documents into authenticated PolicySnapshot objects with source SHA-256 |
|     digests and retriever signatures.                                                             |
+---------------------------------------------------------------------------------------------------+
                                                |
                                                | Signed Evidence & Record Binding
                                                v
+---------------------------------------------------------------------------------------------------+
| DOMAIN 3: TRUSTED INSTITUTIONAL / HUMAN AUTHORIZATION                                             |
|   - Principal / Legal Compliance Officer / Policy Authority                                       |
|   - Issues VersionedAuthorizationRecord binding Principal, Action, Resource, Purpose, Recipient,  |
|     Bound Policy Digest, Expiry, and Revocation. Sets review conditions.                         |
|   - LEGAL ENFORCEABILITY IS DETERMINED HERE BY HUMAN/INSTITUTIONAL AUTHORITIES (NOT SOFTWARE).   |
+---------------------------------------------------------------------------------------------------+
                                                |
                                                | Cryptographically Signed Authorization Record
                                                v
+---------------------------------------------------------------------------------------------------+
| DOMAIN 4: DETERMINISTIC SOFTWARE CONTROL PLANE                                                    |
|   - ConsentAndPolicyDriftGate, TrustedExecutionBoundary, TamperEvidentAuditTrail                  |
|   - Deterministically evaluates structural equality, hash matching, expiration, revocation,      |
|     and purpose constraints. Enforces single-use token consumption. FAILS CLOSED ON ANY AMBIGUITY. |
+---------------------------------------------------------------------------------------------------+
```

### Untrusted Document to Authenticated Observation Pipeline

1. **Fetch & Hash:** Retrieval worker fetches external document text, computes `raw_document_hash = SHA256(bytes)`.
2. **Attest:** Retrieval worker signs `(url, timestamp, raw_document_hash)` with HSM/KMS key, creating `PolicySnapshot`.
3. **Parse & Structure:** Deterministic JSON parser extracts clause definitions (`parsed_clauses`). If parser confidence $< 0.90$, sets `parser_status = UNCERTAIN`.
4. **Anchor:** `PolicySnapshot` digest is anchored to `ImmutableLedgerAdapter`.

---

## 5. Enforceable System Invariants

### 5.1 System Invariants Matrix

| Invariant Code | Invariant Statement | Enforcement Mechanism | Architectural Limitations |
|---|---|---|---|
| **INV-1** | **Evidence Authenticity** | `PolicySnapshot` and `VersionedAuthorizationRecord` must carry valid cryptographic signatures verified against `CryptoAttestationGate` / KMS. | Dependent on KMS key security; host root compromise can forge signatures if keys are local. |
| **INV-2** | **Policy-Baseline Binding** | `baseline_policy_snapshot.raw_document_hash == auth_record.bound_policy_digest`. | None. Fully enforceable deterministically. |
| **INV-3** | **Fail-Closed Evidence** | Missing, expired, revoked, or low-confidence policy evidence MUST yield `GateDecision.HALT` or `DENY`. | None. Fully enforceable inside `ControlPlaneGate.evaluate_safe()`. |
| **INV-4** | **6-Vector Authorization Binding** | Actions allowed ONLY if (Principal, Resource, Action, Purpose, Recipient, Policy Digest) match record grants. | Requires action metadata to be untampered; relies on Domain 2/3 metadata integrity. |
| **INV-5** | **Atomic Single-Use Execution** | Single-use `authorization_token_id` consumed atomically in `TrustedExecutionBoundary` under `threading.Lock`. | Single-node in-memory lock (`threading.Lock`). Distributed multi-node setups require Redis/DLT atomic locks. |
| **INV-6** | **Opt-In Non-Interference** | Unconfigured or legacy workloads MUST pass through unaffected without behavior drift. | Enforced via `GateConfig.enabled` check in `ControlPlaneGate`. |

---

## 6. Abstraction Reuse Assessment

```
+-----------------------------------------------------------------------------------+
|                            ABSTRACTION REUSE ASSESSMENT                           |
+-----------------------------------------------------------------------------------+
| CATEGORY A: SAFELY REUSABLE WITHOUT MODIFICATION                                  |
|   1. ControlPlaneGate, GateInput, GateConfig, GateOutcome, GateDecision           |
|      (epistemicos/gates.py:29-218)                                                |
|   2. LocalProvenanceStore, ProvenanceEvent, ProvenanceReconciler                  |
|      (epistemicos/provenance.py:80-209, 343-438)                                  |
|   3. TamperEvidentAuditTrail, AuditEvent                                          |
|      (epistemicos/audit.py:94-226)                                                |
|   4. TransactionalComplianceBroker, OffChainStoreAdapter, ImmutableLedgerAdapter  |
|      (epistemicos/compliance.py:10-148)                                           |
+-----------------------------------------------------------------------------------+
| CATEGORY B: REUSABLE ONLY WITH ADDITIONAL SECURITY GUARANTEES                     |
|   1. EpistemicOrchestrator (epistemicos/core.py:173)                              |
|      - Requirement: Must authenticate `context` dictionary before passing to gates |
|        or fetch records internally from a trusted store.                          |
|   2. TrustedExecutionBoundary (epistemicos/provenance.py:212)                     |
|      - Requirement: Must bind `transaction_id` and payload digest to signed      |
|        receipts during token validation.                                          |
|   3. ReceiptGenerator (epistemicos/audit.py:280)                                  |
|      - Requirement: `verify_receipt()` must assert `transaction_id` and          |
|        `input_hash` match current execution request context.                      |
+-----------------------------------------------------------------------------------+
```

---

## 7. Deterministic Evaluation Plan

To rigorously measure security and performance without making unverified claims, a measurement plan is established.

### 7.1 Test Suite Strata

1. **Positive Controls ($N=20$):** Valid, un-expired, signed authorization records with matching baseline policies. **Expected:** $100\%$ `GateDecision.ALLOW`, execution succeeds.
2. **Negative Controls ($N=20$):** Expired consents, revoked records, explicitly prohibited purposes. **Expected:** $100\%$ `GateDecision.DENY`, zero execution.
3. **Adversarial Drift Cases ($N=30$):** Unilateral purpose expansion, altered baseline hashes, forged signatures, TOCTOU payload modifications, receipt replay. **Expected:** $100\%$ `GateDecision.HALT` / rejection, zero execution.
4. **Regression / Opt-In Pass-Through ($N=20$):** Standard CPR submissions without consent context. **Expected:** $100\%$ `GateDecision.ALLOW` under legacy pipeline.

### 7.2 Empirical Measurement Protocol
- **Prevention Rate Measurement:** Executed by wrapping protected functions in `TrustedExecutionBoundary` and asserting zero side-effect mutations on `DENY`/`HALT`.
- **Latency Overhead Measurement:** Benchmark via `time.perf_counter_ns()` across 1,000 iterations in `benchmarks/run_pipeline_profiling.py`.

---

## 8. Go / No-Go Recommendation

### Recommendation: **CONDITIONAL GO**

#### Conditions for Proceeding to Implementation:
1. **Condition 1 (Context Authentication):** Do NOT read unauthenticated `context["authorization_record"]` directly from user request dicts. Authorization records must be authenticated via cryptographic signature or fetched via a trusted `AuthorizationRecordRegistry`.
2. **Condition 2 (Policy Digest Enforcement):** The gate MUST assert `baseline_policy_snapshot.raw_document_hash == auth_record.bound_policy_digest` before performing drift analysis.
3. **Condition 3 (Fail-Closed Default):** Missing active policy evidence when required by review conditions MUST yield `GateDecision.HALT`, never `ALLOW`.
4. **Condition 4 (6-Vector Validation):** `ConsentAndPolicyDriftGate` MUST validate all 6 vectors (action, resource, purpose, recipient, effective date, policy digest).
5. **Condition 5 (Opt-In Safety):** `ConsentAndPolicyDriftGate` MUST default to `enabled = False` or pass-through mode when consent context is absent, ensuring zero regressions for existing EpistemicOS pipelines.

---

## Summary Conclusion

This Phase 2 design review successfully addresses the gaps of the initial proposal. By identifying 12 specific vulnerability scenarios, establishing line-by-line codebase citations, defining explicit trust domains, and specifying testable system invariants, this review provides a secure, fail-closed roadmap for implementing Consent Provenance and Policy Drift governance in EpistemicOS.
