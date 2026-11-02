# EpistemicOS Architecture Audit & Phase 1 Remediation: Halt Lifecycle, State Preservation & Controlled Resumability Specification (v1.6.0)

**Author:** Jules (Principal Architecture Subsystem Auditor)
**Document Revision:** `1.6.0` (Original Audit `v1.5.2` + Phase 1 Remediation Addendum)
**Revision Date:** November 2026
**Target Repository:** `sarhodes37-tech/entropy-aware-halting` (`epistemicos`)
**Original Audit Baseline Git Commit SHA:** `26d442d6d7f655b22d08991b08ca206979936311`
**Baseline Commit Date:** Sun Nov 1 08:51:11 2026 -0500 (13:51:11 UTC)
**Baseline Commit Message:** `Merge pull request #326 from sarhodes37-tech/sentinel-harden-token-detection-7855408756707708238`
**Git Branch:** `fix/halt-reconciliation-vector-quarantine-9283081714373314343`
**Audit Scope:** Repository-wide architectural audit of EpistemicOS halt lifecycles, in-flight execution handling, state survival/invalidation rules, recovery semantics, and controlled resumability constraints across `epistemicos/core.py`, `epistemicos/scheduler.py`, `epistemicos/gates.py`, `epistemicos/models.py`, `epistemicos/provenance.py`, `epistemicos/authorization.py`, `epistemicos/containment.py`, `epistemicos/tools.py`, `epistemicos/vector_hygiene.py`, `epistemicos/telemetry.py`, and `epistemicos/shower_curtain/`.
**Status:** ARCHITECTURAL AUDIT WITH PHASE 1 REMEDIATION ADDENDUM (GAP-HALT-06 & GAP-HALT-07 REMEDIATED AND TESTED)

---

## Revision History

| Version | Date | Description of Changes | Author |
| :--- | :--- | :--- | :--- |
| `1.0.0` | Nov 2026 | Initial repository-wide architectural audit of halt lifecycle, state preservation, failure scenarios, and checkpointing invariants. | Jules |
| `1.1.0` | Nov 2026 | Major structural revision decoupling the 4 recovery operations, establishing the 7-state execution outcome model, documenting the `core.py` top-level status ambiguity defect (`GAP-HALT-06`), clarifying `ProvenanceReconciler` boundaries, and specifying multi-scope fencing. | Jules |
| `1.2.0` | Nov 2026 | Consistency and evidence correction revision: temporal metadata grounding against commit `26d442d`, claim-level matrix tags, pre-invocation crash boundary introduction, and initial signal test separation. | Jules |
| `1.3.0` | Nov 2026 | State semantics and test specification errata: timestamp arithmetic, crash boundary refinement, provenance write split, human intervention taxonomy, and POSIX signal returncode conventions. | Jules |
| `1.5.0` | Nov 2026 | Final evidence and consistency corrections: provenance historical completeness vs chain integrity, vector hygiene tracking-loss defect (`GAP-HALT-07`), consistent `NOT_STARTED` classifications, synthetic illustrative timestamp clarification, and test disaggregation. | Jules |
| `1.5.1` | Nov 2026 | Final consistency and precision errata: reconciled test metadata, crash boundary 4 semantics, vector hygiene qualifications, KeyboardInterrupt propagation vs process termination, qualified fail-closed recommendation, and qualified checkpoint candidate eligibility. | Jules |
| `1.5.2` | Nov 2026 | **Final Documentation Consistency Correction:**<br>1. **Section 4.1 Lifecycle Entry Alignment:** Corrected lifecycle diagram entry to state that `core.py` catches `Exception`, not `BaseException`; the exception propagates through the orchestrator to its caller, bypassing orchestrator-level vector revocation and HALT audit logging, terminating the host process only if uncaught at the top-level application boundary.<br>2. **Section 12 GAP-HALT-01 Title Correction:** Renamed GAP-HALT-01 title from "BaseException Process Termination Bypasses Pipeline Cleanup" to "BaseException Propagation Bypasses Pipeline Cleanup", maintaining precise consistency with Sections 4.1, 7.1, 7.2, and 14. | Jules |
| `1.6.0` | Nov 2026 | **Phase 1 Remediation Update:**<br>1. **GAP-HALT-06 Resolved:** Implemented fail-closed `core.py` fix returning top-level `"status": "RECONCILIATION_REQUIRED"` (not `"ALLOWED"`), explicitly aborting `trajectory_scope` to prevent auto-commit on context exit, revoking trajectory vectors, accounting for outstanding vectors across active staging and quarantine in `vectors_pending`, and reporting cleanup outcomes (`vector_cleanup`).<br>2. **GAP-HALT-07 Resolved:** Implemented thread-safe `vector_hygiene.py` fix capturing batches under lock to prevent concurrent staging loss, preserving failed purges in in-memory `_unpurged_vectors` quarantine, propagating explicit backend `False` returns, providing `retry_quarantined_vectors()`, and implementing scope-isolated abort tracking (`_active_scopes`). Note that quarantine is strictly in-memory and not durable across process restarts.<br>3. **Integration Corrections:** Reconciled Section 14 conclusion and recommendations to reflect resolved vs remaining architectural limitations. | Jules |

---

## 1. Auditable Source Baseline & Verification Methodology

### 1.1 Source Baseline & Verification Note
Every claim, citation, and analysis in the original v1.5.2 audit section is strictly grounded in the codebase at the historical baseline commit `26d442d6d7f655b22d08991b08ca206979936311`. Subsequent Phase 1 remediation updates (v1.6.0) document the verified implementation of GAP-HALT-06 and GAP-HALT-07 on branch `fix/halt-reconciliation-vector-quarantine-9283081714373314343`.
- **Repository Remote:** `origin https://github.com/sarhodes37-tech/entropy-aware-halting`
- **Commit SHA:** `26d442d6d7f655b22d08991b08ca206979936311`
- **Commit Date:** Sun Nov 1 08:51:11 2026 -0500 (13:51:11 UTC)
- **Commit Subject:** `Merge pull request #326 from sarhodes37-tech/sentinel-harden-token-detection-7855408756707708238`
- **Active Working Branch:** `jules-9283081714373314343-b47da78e`
- **Execution Runtime:** Linux x86_64, Python 3.12.13
- **Verification Test Command:**
  ```bash
  PYTHONPATH="/home/jules/.local/share/pipx/venvs/pytest/lib/python3.12/site-packages:." python3 -m pytest tests/unit/ -k "not test_reproducible_evaluation"
  ```
- **Test Baseline Metadata Reconciliation:** Across the sequential audit review iterations, four distinct automated test executions were run against the sandbox environment:
  - *Verification Run 1:* `814 passed, 3 skipped, 13 deselected in 56.37s` (0 failures).
  - *Verification Run 2:* `814 passed, 3 skipped, 13 deselected in 62.63s` (0 failures).
  - *Verification Run 3:* `814 passed, 3 skipped, 13 deselected in 70.97s` (0 failures).
  - *Verification Run 4:* `814 passed, 3 skipped, 13 deselected in 74.94s` (0 failures).
  - Skips (consistent across all runs): `test_property_based.py` (hypothesis missing in sandbox), `test_security_coverage_remediation.py:375` (torch optional extra), `test_utils.py:64` (transformers optional extra).
  - Deselected (consistent across all runs): 13 subprocess CLI reproduction tests requiring parent git tree pinning.

### 1.2 Claim Classification Standard
To ensure strict scientific transparency, every architectural claim throughout this specification is evaluated and tagged at the granular claim level using the following vocabulary:
- **`[ENFORCED]`**: Behavior is directly implemented and enforced by production code paths in the repository.
- **`[TESTED]`**: Behavior is directly exercised and verified by an existing automated test in the repository.
- **`[DOCUMENTED]`**: Behavior is described in project documentation, comments, or docstrings, but is not independently enforced by runtime constraints.
- **`[PROPOSED]`**: Future architectural contract or specification introduced by this audit; does not exist in production code today.
- **`[UNKNOWN]`**: Behavior cannot be established from the repository without additional empirical observation or downstream integration evidence.

### 1.3 Critical Distinction: Internal Chain Integrity vs. Historical Completeness `[ENFORCED / DOCUMENTED]`
Inspection of `LocalProvenanceStore._inspect_health()` (`epistemicos/provenance.py:232-273`) establishes a fundamental cryptographic limitation:
- **What `_inspect_health()` Verifies `[ENFORCED & TESTED]`:**
  1. Valid JSON parsing for every non-empty line in the file.
  2. Cryptographic hash chaining: `computed_hash == recorded_hash` and `recorded_prev == expected_prev`.
  3. No duplicate `event_id` strings within the surviving file.
- **What `_inspect_health()` CANNOT Verify (Historical Completeness) `[DOCUMENTED]`:**
  - `_inspect_health()` validates **only the surviving records present on disk**.
  - **Suffix / Trailing Record Deletion Vulnerability:** If one or more complete trailing JSONL records are deleted from the tail of `logs/provenance_audit.jsonl`, the surviving truncated prefix **still forms an unbroken, mathematically valid hash chain originating from `GENESIS_SEED`**.
  - Without an independently trusted external tail anchor (such as periodic checkpointing to an immutable ledger or external high-water sequence register), `LocalProvenanceStore` **cannot detect suffix truncation**.
  - **Inference Impact on Pre-Invocation Crashes:** Consequently, observing a healthy hash chain containing `AUTHORIZATION_GRANTED` but lacking `EXECUTION_STARTED` does **not** prove that `EXECUTION_STARTED` was never written. An incomplete or truncated log can look perfectly healthy. Therefore, in the absence of independent external completeness evidence, the execution invocation status after a crash remains **`[UNKNOWN]`**.

---

## 2. Separation of the Four Recovery Operations

In an autonomous agent security middleware, different recovery operations possess distinct trust requirements, preconditions, and safety implications. Conflating them introduces critical security vulnerabilities.

```
                                  PIPELINE INGRESS
                                         │
                   ┌─────────────────────┼─────────────────────┐
                   ▼                     ▼                     ▼
          [ RE-EVALUATION ]          [ RETRY ]      [ CHECKPOINT RESUMPTION ]
          • Fresh input / context   • Prior attempt failed • Prior state verified
          • Re-enters top of pipe   • Same operation       • Skips prior steps
          • All gates evaluate      • Assesses side effects• Enforces fence & lineage
          • Zero prior authority    • Fresh capability req.• Re-evaluates authority
                   │                     │                     │
                   └─────────────────────┼─────────────────────┘
                                         │
                                         ▼
                        [ EXTERNAL-STATE RECONCILIATION ]
                        • Deterministic probe of downstream system
                        • Evaluates whether external mutation committed
                        • Does NOT authorize retry or resumption
```

### 2.1 Formal Definitions

#### Operation A: Re-Evaluation `[ENFORCED]`
- **Definition:** Initiating a new evaluation of a task using corrected inputs, new observational evidence, or updated conversational context.
- **Pipeline Progression:** Re-enters the normal pipeline from the initial entry point (`process_submission()`).
- **Gating & Authorization:** Evaluates sequentially across all configured governance gates (`ShowerCurtainGate` $\rightarrow$ `EntropyGate` $\rightarrow$ `PermissionGate` $\rightarrow$ `TriangulationGate`) and requires a fresh capability issuance from `AuthorizationAuthority`.
- **Preconditions:** The prior operation must be terminated. No execution authority carries over from the halted attempt.

#### Operation B: Retry `[PROPOSED]`
- **Definition:** Initiating a new execution attempt of the **same underlying operation** following a previous failed or halted attempt.
- **Safety Prerequisite:** Requires an affirmative determination that retrying is safe. Specifically, it requires proof that either:
  1. No external side effect occurred during the prior attempt; or
  2. The target operation is provably idempotent under the identical idempotency key or request digest.
- **Gating & Authorization:** A retry **cannot** reuse the previous capability token (which was permanently consumed at the execution boundary). It requires fresh policy evaluation, active denial checking, and a newly issued single-use capability.

#### Operation C: Checkpoint Resumption `[PROPOSED]`
- **Definition:** Continuing execution of a multi-step workflow from a previously captured, cryptographically verified intermediate execution state.
- **Safety Prerequisite:** Requires verifying checkpoint integrity, lineage, active policy/contract digests, high-water fencing generation across all bound scopes, and atomic single-consumption of the checkpoint artifact.
- **Gating & Authorization:** Restoring application context or reasoning state from a checkpoint **never** restores authorization authority. Every subsequent protected action must be independently evaluated and authorized at the time of dispatch.

#### Operation D: External-State Reconciliation `[PROPOSED]`
- **Definition:** A diagnostic or evidentiary operation that queries authoritative external systems (or evaluates local evidence records) to determine whether a downstream side effect actually occurred when EpistemicOS cannot establish the outcome from its own records.
- **Non-Authorization Principle:** A reconciliation result is diagnostic evidence only. Establishing that a side effect failed or succeeded **does not automatically grant authority to retry, resume, or abort**. Any subsequent action requires an independent authorization decision.

### 2.2 Comparative Recovery Matrix

| Dimension | Re-Evaluation | Retry | Checkpoint Resumption | External-State Reconciliation |
| :--- | :--- | :--- | :--- | :--- |
| **Primary Intent** | Solve task with new/corrected context | Re-execute failed operation | Continue from intermediate step | Determine downstream reality |
| **Pipeline Entry Point** | Top of pipeline (`process_submission`) | Execution boundary dispatch | Intermediate workflow cursor | Out-of-band diagnostic |
| **Requires Fresh Capability?** | **Yes** `[ENFORCED]` | **Yes** `[PROPOSED]` | **Yes** `[PROPOSED]` | **No** (Read-only probe) |
| **Side-Effect Precondition** | None (prior execution finished) | Proof of no side effect or idempotency | Reconciliation of prior steps | Outcome was `OUTCOME_UNKNOWN` |
| **Active Denial Check** | Enforced at authority `[ENFORCED]` | Enforced; blocks retry if denied `[PROPOSED]` | Enforced; blocks resume if denied `[PROPOSED]` | None (diagnostic query) |
| **Fencing Token Rule** | Allocates new generation `[ENFORCED]` | Allocates new generation `[PROPOSED]` | Validates `fencing_token == high_water` `[PROPOSED]` | Evaluates observed fence `[PROPOSED]` |
| **Prohibited Shortcut** | Skipping gates based on past score | Replaying consumed capability | Restoring authorization grant | Automatically triggering retry |

---

## 3. Grounded Execution Outcome State Model & Crash Boundaries

### 3.1 Pre-Invocation Crash Boundaries & The Non-Transactional Atomicity Boundary
Inside `TrustedExecutionBoundary.execute_protected_action()` (`epistemicos/provenance.py:430-512`), the execution boundary executes several distinct steps across separate persistence and invocation layers.

```
[ Candidate State: NOT_STARTED ]
       │
       ▼
(1) Atomic Capability Consumption in Storage
    [provenance.py:442-458; authorization.py:867-913]
       │
       ├─► CRASH BOUNDARY 1: Token marked consumed, but EXECUTION_STARTED write crashes.
       │   Durable Evidence: Token is consumed. No EXECUTION_STARTED in provenance.
       │   Actual Reality: Executor was NEVER invoked.
       │   Reconstructibility Condition: Reconstructible as AUTHORIZATION_CONSUMED_UNINVOKED
       │   ONLY IF the provenance log passes external completeness verification!
       │   Without external completeness proof: Status remains UNKNOWN.
       ▼
(2) Emit EXECUTION_STARTED Event to Provenance Store
    [provenance.py:460-476]
       │
       ├─► CRASH BOUNDARY 2: EXECUTION_STARTED persisted, but host crashes before executor_func() runs.
       │   Durable Evidence: Token is consumed. EXECUTION_STARTED exists on disk. No terminal event.
       │   Actual Reality: Executor was NEVER invoked.
       │   Reconstructibility: AMBIGUOUS [UNKNOWN]. Post-crash inspection CANNOT distinguish
       │   a crash immediately before executor invocation from a crash during early executor execution!
       ▼
(3) Invoke Callable: executor_func()
    [provenance.py:504-512]
       │
       ├─► CRASH BOUNDARY 3: Callable running; exception, kill signal, or network drop mid-call.
       │   Durable Evidence: Token is consumed. EXECUTION_STARTED exists.
       │   Actual Reality: External side effects may be partial, full, or zero.
       │   Reconstructibility: OUTCOME_UNKNOWN. External reconciliation strictly required.
       ▼
(4) Return / Verification / Terminal Provenance Recording
    [provenance.py:559-616]
       │
       ├─► CRASH BOUNDARY 4: Callable returned cleanly, but writing EXECUTION_SUCCEEDED throws.
       │   Durable Evidence: Token is consumed. EXECUTION_STARTED exists. No EXECUTION_SUCCEEDED on disk.
       │   Execution Reality: Callable returned in memory (RUNTIME_RETURNED established).
       │   Downstream Reality: Durable transaction completion depends on executor contract & downstream systems.
       │   Control-Plane State: CONTROL_PLANE_COMPLETED is NOT established (terminal provenance failed).
       │   Runtime Return: EXECUTION_OUTCOME_UNKNOWN with recovery_required=True.
       ▼
[ CONTROL_PLANE_COMPLETED ] (Local evidence verified)
       │
       ▼
[ EXTERNAL_EFFECT_CONFIRMED ] (Requires downstream authoritative verification)
```

### 3.2 The Non-Transactional Atomicity Boundary `[DOCUMENTED]`
- **The Inherent Boundary:** EpistemicOS tool executors are arbitrary Python callables invoking external REST APIs, CLI binaries, databases, and local files. For arbitrary, non-transactional callables, **a durable local write and an executor invocation cannot be made atomic on a POSIX filesystem**.
- **Limitations of Distributed Transaction Protocols:** Distributed two-phase commit (2PC) or XA protocols cannot solve this generally. Distributed transactional coordination is applicable **only** where the downstream system participates in a compatible transaction protocol. For arbitrary HTTP requests, subprocess commands, or uncoordinated external services, this boundary represents an **unavoidable physical limit**.
- **No Silver Bullet Event:** Emitting an additional intermediate disk event (e.g. `EXECUTION_INVOCATION_IMMINENT`) merely shifts and narrows the uncertainty window; it does **not** make durable disk persistence and memory invocation atomic.
- **Qualified Non-Invocation Inference Rule `[DOCUMENTED]`:**
  A consumed capability accompanied by the absence of an `EXECUTION_STARTED` event establishes non-invocation **if and only if the relevant provenance log has passed integrity verification (`_inspect_health()`) AND independent completeness verification proves that trailing records were not truncated or deleted**. In the absence of an external tail anchor, non-invocation cannot be proven from local logs alone, and the invocation state remains **`[UNKNOWN]`**.

### 3.3 Formal State Dimensions: Runtime, Durable, and Proposed States

To eliminate conflation between conceptual ideals and verifiable runtime records, EpistemicOS separates execution states into three explicit dimensions:

#### A. Transient Runtime Observations (Observed during live in-memory execution)
- **`RUNTIME_PRE_DISPATCH` `[ENFORCED]`**: Execution boundary has verified capability, but has not yet called storage consumption.
- **`RUNTIME_EXECUTOR_ACTIVE` `[ENFORCED]`**: Storage consumption and `EXECUTION_STARTED` logging completed; thread is currently executing `executor_func()`.
- **`RUNTIME_RETURNED` `[ENFORCED]`**: Callable returned a Python object without unhandled exception.
- **`RUNTIME_EXCEPTION` `[ENFORCED]`**: Callable raised a Python exception.

#### B. Durable Control-Plane Evidence (Verifiable from on-disk append-only logs)
- **`DURABLE_TOKEN_CONSUMED` `[ENFORCED]`**: Capability token marked consumed in `AuthorizationStore` journal.
- **`DURABLE_STARTED_RECORDED` `[ENFORCED]`**: Provenance log contains an unbroken `EXECUTION_STARTED` event with valid chain hash.
- **`CONTROL_PLANE_COMPLETED` `[ENFORCED]`**: Provenance log contains valid `EXECUTION_SUCCEEDED` event and verified evidence keys.
- **`CONTROL_PLANE_FAILED` `[ENFORCED]`**: Provenance log contains valid `EXECUTION_FAILED` event.
- **`CONTROL_PLANE_INTERRUPTED` `[ENFORCED]`**: Provenance log contains valid `EXECUTION_INTERRUPTED` event.
- **`CONTROL_PLANE_INCOMPLETE` `[DOCUMENTED DERIVED FINDING]`**: Derived audit finding when `ProvenanceReconciler` evaluates a log containing `EXECUTION_STARTED` without any terminal event (`status: "INCOMPLETE_EVIDENCE"`). It is an evaluative finding, not an event type written to the log.

#### C. Proposed Lifecycle & Downstream Outcome States
- **`NOT_STARTED` `[PROPOSED]`**: Proposed initial lifecycle state representing zero authorization consumed and zero execution dispatched. It is not an implemented runtime state object.
- **`AUTHORIZATION_CONSUMED_UNINVOKED` `[PROPOSED]`**: Proposed state where token was consumed in storage, but verified healthy logs and external completeness evidence prove `EXECUTION_STARTED` was never written.
- **`EXTERNAL_EFFECT_CONFIRMED` `[PROPOSED]`**: Authoritative external query or idempotent receipt confirms downstream transaction committed.
- **`PARTIAL_SIDE_EFFECT_CONFIRMED` `[PROPOSED]`**: Downstream query confirms partial state mutation occurred before failure.
- **`OUTCOME_UNKNOWN` `[PROPOSED]`**: Execution began or was durably recorded, but external downstream state cannot be established from available records.
- **`RECONCILIATION_REQUIRED` `[PROPOSED]`**: Operation quarantined pending external query.

### 3.4 Narrowed Analysis of `OUTCOME_UNKNOWN` Enforcement
- **`[ENFORCED & TESTED]` Returned by Execution Boundary:** In `epistemicos/provenance.py:606-616`, if `executor_func()` returns successfully but `store.record_event(success_event)` throws an exception, the boundary returns:
  ```python
  return {
      "status": "EXECUTION_OUTCOME_UNKNOWN",
      "result": result,
      "attempt_id": attempt_id,
      "audit_recording_failed": True,
      "recovery_required": True,
      "reason": f"Execution completed but terminal audit logging failed: {str(audit_err)}"
  }
  ```
- **`[ENFORCED & TESTED]` Detected by Provenance Reconciler:** In `epistemicos/provenance.py:716-718`, if `auth_granted` and `exec_started` exist for a correlation ID, but no terminal event exists, `reconcile_correlation()` returns `valid: False`, `status: "INCOMPLETE_EVIDENCE"`.
- **`[ENFORCED & TESTED]` Top-Level Orchestrator Quarantine:** In `core.py`, when `out_status == "EXECUTION_OUTCOME_UNKNOWN"`, `core.py` halts execution, revokes trajectory vectors, logs a pipeline `HALT` audit event, and returns top-level `"status": "RECONCILIATION_REQUIRED"` with `vector_cleanup` reporting (`GAP-HALT-06 remediation`).
- **`[PROPOSED]` Universal Runtime Quarantine:** The rule that `OUTCOME_UNKNOWN` must actively block automated retry and fail closed across all callers is a **proposed policy contract**, not currently enforced across the entire middleware.

---

## 4. Current-State Lifecycle & Top-Level Response Ambiguity

### 4.1 Execution Lifecycle Map (Verified Source References)

```
Caller: process_submission(raw_payload, context, trajectory_id)
 ├─► reset_trajectory(traj_id)                                  [core.py:475, 106-113] [ENFORCED]
 ├─► _validate_and_normalize(raw_payload)                        [core.py:175-207]      [ENFORCED, TESTED]
 │    └─► Error: logs AuditEvent(HALT); returns {"status": "HALTED", "reason": "Schema validation failed"}
 ├─► ResourceProfiler & VectorHygieneManager.trajectory_scope()  [core.py:272-276]      [ENFORCED, TESTED]
 ├─► LocalProvenanceStore.record_event(ACTION_PROPOSED)          [core.py:284-332]      [ENFORCED, TESTED]
 │    └─► Write failure: revoke_trajectory(); logs HALT; returns {"status": "HALTED", "execution_status": "DENIED"}
 ├─► _evaluate_gates(payload_dump, context)                      [core.py:218-270]      [ENFORCED, TESTED]
 │    └─► Any gate HALT/DENY: revoke_trajectory(); logs HALT;
 │        records AUTHORIZATION_DENIED; returns {"status": "HALTED", "gate": ..., "reason": ...}
 ├─► AuthorizationAuthority.evaluate_and_issue_capability()      [core.py:456-515]      [ENFORCED, TESTED]
 │    ├─► Checks denial_registry.jsonl (_check_denial_unlocked)  [authorization.py:1869][ENFORCED, TESTED]
 │    ├─► Validates TrustedTaskContract & signatures             [authorization.py:1902][ENFORCED, TESTED]
 │    ├─► Validates Policy operations, resources, approvers      [authorization.py:1931][ENFORCED, TESTED]
 │    └─► If Denied: records denial to disk; revoke_trajectory(); records AUTHORIZATION_DENIED;
 │                   returns {"status": "HALTED", "execution_status": "DENIED"}
 ├─► LocalProvenanceStore.record_event(AUTHORIZATION_GRANTED)    [core.py:517-550]      [ENFORCED, TESTED]
 ├─► store.get_events_for_correlation(corr_id)                  [core.py:552-578]      [ENFORCED, TESTED]
 │    └─► Grant missing/unreadable: returns {"status": "HALTED", "execution_status": "DENIED"}
 └─► TrustedExecutionBoundary.execute_protected_action()         [core.py:580-664]      [ENFORCED, TESTED]
      ├─► Pre-checks: verify_capability(), digest match, executor identity ('is') [provenance.py:390-440] [ENFORCED, TESTED]
      ├─► [LINEARIZATION POINT] Atomic consume_capability(token_id)                [provenance.py:442-458] [ENFORCED, TESTED]
      ├─► LocalProvenanceStore.record_event(EXECUTION_STARTED)                     [provenance.py:460-476] [ENFORCED, TESTED]
      ├─► executor_func() invocation                                               [provenance.py:504-512] [ENFORCED, TESTED]
      │    ├─► Exception: records EXECUTION_FAILED; re-raises e                    [provenance.py:513-535] [ENFORCED, TESTED]
      │    │              core.py catches Exception; revoke_trajectory();
      │    │              returns {"status": "HALTED", "execution_status": "EXECUTION_FAILED"} [core.py:651-664]
      │    └─► BaseException: records EXECUTION_INTERRUPTED; re-raises be          [provenance.py:536-557] [ENFORCED, TESTED]
      │                       core.py catches Exception, NOT BaseException; exception propagates to caller;
      │                       orchestrator vector revocation & HALT audit bypassed; process terminates only if uncaught at top-level boundary [core.py:651] [GAP-HALT-01]
      ├─► _verify_success_evidence(result)                                         [provenance.py:478-502] [ENFORCED, TESTED]
      │    └─► Evidence missing: records EXECUTION_FAILED (UNVERIFIED_SUCCESS);
      │                          returns {"status": "UNVERIFIED_SUCCESS"}
      │                          core.py catches; returns {"status": "HALTED", "execution_status": "UNVERIFIED_SUCCESS"}
      └─► LocalProvenanceStore.record_event(EXECUTION_SUCCEEDED)                   [provenance.py:592-616] [ENFORCED, TESTED]
           └─► Write failure: returns {"status": "EXECUTION_OUTCOME_UNKNOWN", "audit_recording_failed": True, "recovery_required": True}
               core.py sets execution_status = "EXECUTION_OUTCOME_UNKNOWN"
               AND PROCEEDS TO PIPELINE SUCCESS PATH! [core.py:747-748, 808-819] [AMBIGUITY DEFECT]
```

### 4.2 Critical Defect: Top-Level Outcome Status Ambiguity in `core.py`

#### Verified Code Path `[ENFORCED]`
Lines 745–820 of `epistemicos/core.py` contain a material status reporting ambiguity:
1. In `core.py:747-748`:
   ```python
   if out_status == "EXECUTION_OUTCOME_UNKNOWN":
       execution_status = "EXECUTION_OUTCOME_UNKNOWN"
   ```
2. Unlike the `UNVERIFIED_SUCCESS` branch (lines 749–768), which executes an immediate return of `{"status": "HALTED", ...}`, the `EXECUTION_OUTCOME_UNKNOWN` branch does **not** return.
3. Instead, control drops down to line 800 (`# 3c. Pipeline Success`), commits staged vectors, logs `AuditLogLevel.INFO` (`gate_name="Pipeline_Complete"`), and returns (lines 808–815):
   ```python
   return {
       "status": "ALLOWED",
       "execution_status": execution_status,
       "masked_payload": cpr.mask_egress_payload(),
       "telemetry": telemetry.__dict__,
       "trajectory_id": traj_id,
       "execution_outcome": execution_outcome
   }
   ```

#### Failure Impact & Caller Misinterpretation `[DOCUMENTED]`
- **Ambiguity:** The orchestrator emits a top-level `"status": "ALLOWED"`. Upstream client adapters or automated callers checking only `res.get("status") == "ALLOWED"` will treat the operation as fully authorized and completed.
- **Safety Violation:** The external execution outcome is explicitly unknown because post-execution persistence crashed. Staged vector embeddings are promoted to the primary index even though execution durability is unconfirmed.
- **Desired Contract `[PROPOSED]`:**
  The top-level response must decouple:
  1. `authorization_status`: `"GRANTED"`
  2. `dispatch_status`: `"DISPATCHED"`
  3. `execution_outcome`: `"OUTCOME_UNKNOWN"`
  4. `pipeline_status`: `"RECONCILIATION_REQUIRED"` (Never `"ALLOWED"` when execution outcome is unknown).

---

## 5. Grounded Assessment of `ProvenanceReconciler`

### 5.1 Verified Code Capabilities
Inspection of `epistemicos/provenance.py:619-725` establishes the exact capabilities of `ProvenanceReconciler.reconcile_correlation()`:
- **`[ENFORCED & TESTED]` Rule 1:** Detects execution started without matching authorization (`exec_started and not auth_granted`).
- **`[ENFORCED & TESTED]` Rule 2:** Detects execution started for an action that was denied (`auth_denied and exec_started`).
- **`[ENFORCED & TESTED]` Rules 3 & 4:** Detects execution target, action name, or canonical request digest mismatches between authorization grant and execution start.
- **`[ENFORCED & TESTED]` Rule 5:** Detects agent false success claims (`agent_claimed_success and not exec_succeeded`).
- **`[ENFORCED & TESTED]` Rule 6:** Detects multiple execution attempts for a single-use authorization token (`token_exec_counts[tok] > 1`).
- **`[ENFORCED & TESTED]` Rule 7:** Detects missing terminal execution events (`exec_started` exists without matching `exec_succeeded`, `exec_failed`, or `exec_interrupted`).
- **`[ENFORCED & TESTED]` Rule 8:** Detects Shower Curtain egress blocks when agent claims success.

### 5.2 What `ProvenanceReconciler` CANNOT Do `[CRITICAL ARCHITECTURAL LIMITATION]`
- **No Downstream Transaction Probing `[ENFORCED]`:** `ProvenanceReconciler` reads **only** local EpistemicOS provenance events (`List[ProvenanceEvent]`). It has **zero interfaces** to query external databases, REST APIs, cloud providers, message queues, or filesystems.
- **Control-Plane Evidence vs. Reality `[DOCUMENTED]`:**
  - If an executor partially wrote to a database and crashed, `ProvenanceReconciler` reports `status: "RECONCILED"` if an `EXECUTION_FAILED` event is present. It **cannot** know that the external database contains orphan mutated rows.
  - If an external API call succeeded but the local process died before logging `EXECUTION_SUCCEEDED`, the reconciler reports `status: "INCOMPLETE_EVIDENCE"` or `violations: ["Execution started but missing terminal outcome event"]`. It **cannot** determine whether the remote API executed the call.
- **Architectural Boundary:** `ProvenanceReconciler` is a **control-plane audit-trail consistency validator**, not a distributed transaction coordinator.

---

## 6. Human Approval Escalation vs. Explicit Denial vs. Administrative Clearance

A critical requirement of this revision is to eliminate confusion between human approval escalation, active authorization denials, and administrative clearance.

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   AUTHORIZATION EVALUATION PATHS                                       │
└───────────────────────────────────┬───────────────────────────────────┬────────────────────────────────┘
                                    │                                   │
                                    ▼                                   ▼
                   [ Condition 1: Human Approval Needed ]     [ Condition 2: Explicit Policy Denial ]
                   • Action requires human approval           • Operation not allowed, target out
                   • Reason: STOP_AND_ESCALATE_...            • Downward restriction active
                   • NO active denial journal entry!          • ACTIVE entry recorded in journal!
                                    │                                   │
                                    ▼                                   ▼
                   [ Checkpoint Status: SUSPENDED ]           [ Checkpoint Status: INVALIDATED ]
                   • Checkpoint remains coherent              • Checkpoint permanently dead
                   • Resumption requires signed approval      • Clearing denial does NOT revive it
                                    │                                   │
                                    ▼                                   ▼
                   [ Resumption with Signed Approval ]        [ Administrative CLEAR_DENIAL ]
                   • Validates approval signature & digest    • Removes block for future proposals
                   • Issues NEW capability                    • Requires fresh proposal & capability
```

### 6.1 Condition 1: Pending Human-Approval Escalation (`STOP_AND_ESCALATE...`) `[ENFORCED & TESTED]`
- **Code Path:** `epistemicos/authorization.py:1963-1965`.
- **Nature:** A benign pause condition where policy mandates four-eyes approval for a sensitive action.
- **Journal State:** **No active denial is written to `logs/denial_registry.jsonl`**.
- **Checkpoint Implication `[PROPOSED]`:** A candidate checkpoint captured prior to this escalation remains structurally and epistemically coherent. It enters a `SUSPENDED_PENDING_APPROVAL` candidate state. It may be resumed **if and only if** a valid, signed `HumanApprovalRecord` matching the exact canonical request digest is supplied, resulting in fresh capability issuance. Supplying approval initiates a **fresh proposal flow**, not an execution retry (since execution never began).

### 6.2 Condition 2: Explicit Authorization Denial (`AUTHORIZATION_DENIED`) `[ENFORCED & TESTED]`
- **Code Path:** `epistemicos/authorization.py:1931-1952` and `epistemicos/core.py:478-515`.
- **Nature:** A security violation (unauthorized operation, restricted target, unmapped identity).
- **Journal State:** An `ACTIVE` denial record is flushed and fsynced to `logs/denial_registry.jsonl`.
- **Checkpoint Implication `[PROPOSED]`:** An explicit denial **permanently invalidates** any existing candidate checkpoint for that task. The checkpoint cannot be resumed.

### 6.3 Condition 3: Administrative Denial Clearance (`CLEAR_DENIAL`) `[ENFORCED & TESTED]`
- **Code Path:** `epistemicos/authorization.py:1278-1400`.
- **Nature:** An administrative state transition appending a `CLEARED` record to `logs/denial_registry.jsonl` and consuming `reauthorization_record.approval_id`.
- **What it DOES NOT Do `[ENFORCED]`:**
  - It does **not** grant execution authority.
  - It does **not** revive previous capability tokens (they remain consumed).
  - It does **not** revive old checkpoints (they remain invalidated).
- **Subsequent Action:** The client must formulate a **new task proposal** that evaluates through the pipeline and obtains a fresh single-use capability.

---

## 7. Process Control, Interruption & Exception Handling

### 7.1 Re-Inspection of `provenance.py` and `core.py`
In `epistemicos/provenance.py:536-557` `[ENFORCED & TESTED]`:
```python
except BaseException as be:
    end_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    interrupt_event = ProvenanceEvent(..., event_type=ProvenanceEventType.EXECUTION_INTERRUPTED.value, outcome={"status": "INTERRUPTED", "reason": str(be)})
    try:
        self.store.record_event(interrupt_event)
    except Exception:
        pass
    raise
```
And in `epistemicos/core.py:651` `[ENFORCED]`:
```python
except Exception as e:
    ...
```

### 7.2 Detailed `BaseException` Stack Unwinding Analysis `[ENFORCED]`
When a synchronous Python interruption occurs (such as `KeyboardInterrupt` / `SIGINT`):
1. **Inside `TrustedExecutionBoundary` (`provenance.py:536-557`):**
   - Caught by `except BaseException as be:`.
   - Attempts best-effort write of `ProvenanceEvent(event_type=EXECUTION_INTERRUPTED)`.
   - Token remains marked consumed in `AuthorizationStore` (consumed at line 448).
   - Re-raises `be`.
2. **Unwinding `VectorHygieneManager.trajectory_scope` (`vector_hygiene.py:115-127`):**
   - The context manager has `except Exception as err:`.
   - **`KeyboardInterrupt` inherits from `BaseException`, NOT `Exception`!**
   - Therefore, the `except Exception` block in `trajectory_scope` is **completely bypassed**!
   - `revoke_trajectory()` is **never called** by the context manager on `KeyboardInterrupt`. Staged vectors remain unpurged in backend storage!
3. **Unwinding `ResourceProfiler` (`telemetry.py:68-77`):**
   - `ResourceProfiler.__exit__(self, exc_type, exc_val, exc_tb)` does **not** specify `except Exception:`. It executes its normal cleanup block unconditionally during stack unwinding. Wall-clock timing is finalized.
4. **Unwinding `EpistemicOrchestrator._execute_pipeline` (`core.py:651`):**
   - The boundary call is wrapped in `except Exception as e:`.
   - `KeyboardInterrupt` is a catchable Python `BaseException`. Because the inspected orchestrator handlers catch `Exception`, the `KeyboardInterrupt` escapes the orchestrator and reaches the caller.
   - Vector revocation fallback at line 653 is bypassed.
   - Audit logging (`_log_pipeline_event(AuditLogLevel.HALT)`) is bypassed.
   - The exception unrolls to the top-level calling framework. It terminates the host process **only if the exception remains uncaught** at the top-level application boundary. (Unlike `SIGKILL`, which is uncatchable and prevents all cleanup handlers from running).

### 7.3 Synchronous Control Flow vs. Downstream Execution Reality `[DOCUMENTED]`
- **Python Control-Flow Termination:** Terminating the Python thread or process stops execution within the host Python runtime.
- **Downstream Reality:** Terminating the Python caller does **not** cancel or roll back an already-dispatched network request, an external database transaction in progress, or a background worker process. The remote server may continue processing and commit side effects after the client process exits.
- **Indeterminate Side Effects:** Unless downstream systems provide authoritative query or compensation protocols, the external state following an interruption remains **`[UNKNOWN]`**.

---

## 8. Vector Hygiene: Cleanup Attempt vs. Confirmed Rollback

### 8.1 Implementation Inspection of Vector Purge
Inspection of `epistemicos/vector_hygiene.py:64-90` establishes two distinct failure modes in vector rollback:

```python
def revoke_trajectory(self, trajectory_id: str, namespace: Optional[str] = None) -> List[Union[str, int]]:
    with self._lock:
        revoked_ids = self._active_trajectories.pop(trajectory_id, [])  # LINE 71: Discards tracking IDs FIRST!

    if not revoked_ids:
        return []

    success = self.adapter.purge_vectors(revoked_ids, namespace=namespace)  # LINE 79: Purge attempt

    if success:
        logger.info(...)
    else:
        logger.error(...)  # LINE 84: Purge failed! But IDs are already popped and lost from tracking!

    return revoked_ids  # Returns revoked_ids as if revoked regardless of success!
```
And in `VectorStoreAdapter.purge_vectors()` (`vector_hygiene.py:21-48`):
```python
except Exception as e:
    logger.error(f"Failed to execute backend vector deletion: {e}", exc_info=True)
    return False
```

### 8.2 Architectural Realities of Vector Cleanup `[ENFORCED / DOCUMENTED]`
1. **Best-Effort Attempt, Not Guaranteed Rollback `[ENFORCED]`:** On ordinary exceptions, `revoke_trajectory()` is invoked, but successful backend deletion is conditional upon the backend database adapter succeeding. If Pinecone, Qdrant, or ChromaDB returns an error or network timeout, `purge_vectors()` returns `False`.
2. **Loss of Tracking References on Failure (`GAP-HALT-07`) `[ENFORCED]`:** Because `pop(trajectory_id)` removes the vector IDs from `_active_trajectories` **before** calling `self.adapter.purge_vectors()`, a backend failure leaves the staged vectors in the vector database while EpistemicOS loses all in-memory references to them. Subsequent calls cannot re-attempt deletion.
3. **Misleading Return Values `[ENFORCED]`:** `revoke_trajectory()` returns `revoked_ids` (the list of popped IDs) even when `purge_vectors()` returns `False`. In `core.py:339`, `actual_revoked_count = len(revoked_ids)` is reported in audit logs as `Vectors Revoked: N`, creating the false appearance of successful rollback.

---

## 9. Scheduler State Lifecycle & Deconstruction of `best_state`

### 9.1 Trajectory State Ingress Reset
Inspection of `epistemicos/core.py:475` establishes the following concrete behavior:
```python
def process_submission(self, raw_payload, context, trajectory_id=None, **kwargs):
    traj_id = trajectory_id or str(uuid.uuid4())
    self.reset_trajectory(traj_id)  # Lines 475 & 106-113
    if hasattr(self.scheduler, "reset"):
        self.scheduler.reset()
```
And in `core.py:106-113`:
```python
def reset_trajectory(self, trajectory_id: str) -> None:
    with self._registry_lock:
        if trajectory_id in self._schedulers:
            self._schedulers[trajectory_id].reset()
            del self._schedulers[trajectory_id]
        if trajectory_id in self._trajectory_locks:
            del self._trajectory_locks[trajectory_id]
```

### 9.2 Architectural Implications
1. **No In-Memory Recovery Mechanism `[ENFORCED]`:** Because `process_submission()` actively deletes and resets `self._schedulers[traj_id]` at ingress, in-memory scheduler state **does not survive resubmission**. Calling `process_submission()` with the same `trajectory_id` wipes `entropy_history`, `utility_history`, and `best_state`.
2. **Deconstruction of `best_state` `[ENFORCED]`:** In `epistemicos/scheduler.py:218-222`, `best_state` is simply the application state object associated with the highest scalar utility value ($U = V \cdot (H_0 - H) - \text{Cost}$). It is an **optimization search artifact**, not a security-validated checkpoint. It contains no cryptographic digests, no provenance links, no policy bindings, and no authority.
3. **Three Distinct Lifecycles:**
   - *Temporary In-Process Retention:* Exists only while the process remains alive and before `reset_trajectory()` is called. `[ENFORCED]`
   - *State Discarded on Resubmission:* Wiped immediately upon calling `process_submission()`. `[ENFORCED & TESTED]`
   - *State Lost on Process Restart:* `EntropyAwareScheduler` has zero persistence backing; process restart destroys all scheduler history. `[ENFORCED]`

---

## 10. Revised Checkpoint Contract (Specification Only)

*Notice: This contract specifies structural and cryptographic requirements for future implementation. Checkpointing is not implemented in the current repository. All timestamps in this example are synthetic illustrative timestamps.*

```json
{
  "$schema": "https://epistemicos.dev/schemas/checkpoint.v1.5.json",
  "checkpoint_id": "CHK-UUID-V4-EXAMPLE",
  "schema_version": "1.5.0",
  "trajectory_id": "TRAJ-UUID-V4-EXAMPLE",
  "correlation_id": "CORR-UUID-V4-EXAMPLE",
  "task_id": "TASK-12345",
  "originating_execution_attempt_id": "ATT-INIT-001",
  "canonical_input_digest": "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",

  "synthetic_illustrative_timestamps": {
    "created_at_utc": "2026-11-01T12:00:00Z",
    "expires_at_utc": "2026-11-01T13:00:00Z",
    "expires_at_epoch": 1793538000.0,
    "validity_window_seconds": 3600.0,
    "chronological_verification": "Arithmetic verified: epoch 1793538000.0 corresponds exactly to 2026-11-01T13:00:00Z (created + 1 hour). Note: This is a synthetic illustrative example; both timestamps precede the baseline commit timestamp of 2026-11-01T13:51:11Z."
  },

  "lineage_and_provenance": {
    "last_provenance_event_id": "EVT-UUID-V4-EXAMPLE",
    "last_provenance_sequence": 14,
    "last_provenance_entry_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "last_audit_receipt_hash": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
  },

  "governance_bindings": {
    "policy_version": "1.0.0",
    "policy_digest": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    "contract_version": "1.0.0",
    "contract_digest": "cb8379ac2098aa165029e3938a51da0bcecfc008fd6795f401178647f96c5b34",
    "active_denial_journal_sequence": 42
  },

  "multi_scope_fencing": {
    "bound_scopes": [
      {
        "scope_key": "task:TASK-12345|target:api.internal.corp:/records",
        "observed_fencing_generation": 4
      },
      {
        "scope_key": "task:TASK-12345|target:storage.internal.corp:/blobs",
        "observed_fencing_generation": 2
      }
    ]
  },

  "external_actions_ledger": [
    {
      "action_name": "fetch_record",
      "target": "target:api.internal.corp:/records/42",
      "execution_attempt_id": "ATT-001",
      "canonical_request_digest": "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b",
      "outcome_state": "EXTERNAL_EFFECT_CONFIRMED",
      "downstream_idempotency_key": "IDEMP-KEY-998811",
      "downstream_tx_reference": "TX-REC-42",
      "provenance_event_id": "EVT-012"
    }
  ],

  "application_state_snapshot": {
    "workflow_cursor": "STEP_3_FETCH_COMPLETED",
    "intermediate_state_digest": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
    "opaque_state_blob": "ZXhhbXBsZV9zdGF0ZV9ibG9iX2NvbnRlbnQ="
  },

  "integrity_attestation": {
    "signing_algorithm": "HMAC-SHA256",
    "signer_identity": "EpistemicOS_Checkpoint_Authority",
    "signature": "fc8252c8dc55839967c58b9ad755a59b61b67c13227dd3080e036c051640744e"
  }
}
```

### 10.1 Core Checkpoint Invariants `[PROPOSED]`

1. **Non-Authority Principle:** A checkpoint is an evidentiary attestation of past state, **never** an authorization grant. Restoring a checkpoint restores application state, but **zero execution authority**.
2. **Multi-Scope Fencing Invariant:** Tasks frequently cross resource targets (e.g. reading from a DB, writing to a bucket). A checkpoint must bind an array of `bound_scopes`. Resumption is permitted **only if every bound scope** satisfies `observed_fencing_generation == current_authoritative_generation`. If any scope has advanced, the entire checkpoint is stale and rejected.
3. **Atomic Single-Consumption & Crash Consistency:** Resuming a checkpoint must atomically transition its status from `AVAILABLE` to `CONSUMED` in durable storage under POSIX flock / transaction locking. If the process crashes during resumption after checkpoint consumption, the checkpoint remains consumed; it cannot be replayed.
4. **External Ledger & No-Replay:** Actions recorded as `EXTERNAL_EFFECT_CONFIRMED` in the `external_actions_ledger` can never be re-executed during resumption. If downstream status is `OUTCOME_UNKNOWN`, resumption is blocked until external reconciliation is complete.
5. **Local `fcntl.flock` Scope Limitation:** Advisory file locking (`fcntl.flock`) is local to a single operating system kernel. In multi-node distributed environments without a distributed transactional consensus store (e.g. Raft/etcd), local file locking cannot guarantee cross-host mutual exclusion.

---

## 11. Revised Halt Classification & State Preservation Matrices

### 11.1 Revised Halt Classification Matrix

*Note on Matrix Classification:* In this revised v1.5.1 matrix, every column is evaluated independently. Current runtime halting behavior is classified as `[ENFORCED]` and/or `[TESTED]`. Prospective checkpoint resumption entries are explicitly tagged `[PROPOSED: CANDIDATE ELIGIBILITY]` to emphasize that they represent candidate design rules conditional upon an independently verified checkpoint existing (no checkpointing mechanism exists today). `NOT_STARTED` is classified as `[PROPOSED]` across all rows.

| Category | Triggering Component & Code Reference | Current Halted Status & Enforcement | Execution Begun? | Side Effects Possible? | Outcome State | Re-Evaluation Permitted? `[PROPOSED]` | Retry Permitted? `[PROPOSED]` | Candidate Checkpoint Resume Eligibility `[PROPOSED: CONDITIONAL ON CHECKPOINT]` | Human Intervention Required? `[PROPOSED]` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **A. Epistemic** | `EntropyGate.evaluate_contract()` (`gates.py:270-305`) | `status: "HALTED"` `[ENFORCED & TESTED]` | No `[ENFORCED]` | No `[ENFORCED]` | `NOT_STARTED` `[PROPOSED]` | **Yes** (with sanitized context) | N/A (no exec) | **Candidate Eligible** (if prior step checkpoint exists) | None |
| **A. Epistemic** | `EntropyGate.evaluate_contract()` (`gates.py:257-268`) | `status: "HALTED"` `[ENFORCED & TESTED]` | No `[ENFORCED]` | No `[ENFORCED]` | `NOT_STARTED` `[PROPOSED]` | **Yes** (supply logprobs) | N/A (no exec) | **Candidate Eligible** | None |
| **A. Epistemic** | `EntropyAwareScheduler.step()` (`scheduler.py:224-242`) | Directive: `NEGATIVE_YIELD`, `halt: True` `[ENFORCED & TESTED]` | Caller loop dependent | Local compute only | `NOT_STARTED` `[PROPOSED]` | **Yes** (re-prompt / change seed) | N/A (no exec) | **Candidate Eligible** (from valid prior checkpoint) | None |
| **A. Epistemic** | `EntropyAwareScheduler.step()` (`scheduler.py:231-236`) | Directive: `IRREDUCIBLE_UNCERTAINTY`, `halt: True` `[ENFORCED & TESTED]` | Caller loop dependent | Local compute only | `NOT_STARTED` `[PROPOSED]` | **Yes** (with prompt guidance) | N/A (no exec) | **Candidate Eligible** (with prompt guidance) | None |
| **A. Epistemic** | `TriangulationGate.evaluate_contract()` (`gates.py:522-545`) | `status: "HALTED"` `[ENFORCED & TESTED]` | No `[ENFORCED]` | No `[ENFORCED]` | `NOT_STARTED` `[PROPOSED]` | **Yes** (with uncorrupted data) | N/A (no exec) | **Ineligible** (data integrity suspect) | None |
| **B. Structural** | `core.py:_validate_and_normalize()` (`core.py:175-207`) | `status: "HALTED"` `[ENFORCED & TESTED]` | No `[ENFORCED]` | No `[ENFORCED]` | `NOT_STARTED` `[PROPOSED]` | **Yes** (correct payload) | N/A (no exec) | N/A (invalid input) | None |
| **B. Structural** | `core.py:_evaluate_gates()` (`core.py:222-232`) | `status: "HALTED"` `[ENFORCED & TESTED]` | No `[ENFORCED]` | No `[ENFORCED]` | `NOT_STARTED` `[PROPOSED]` | **Yes** (after fixing gate bug) | N/A (no exec) | **Candidate Eligible** | None |
| **B. Structural** | `TrustedExecutionBoundary` Pre-Dispatch Store Failure (`provenance.py:460-476`) | `store.record_event(EXECUTION_STARTED)` throws `[ENFORCED]` | **No** (throws before callable) `[ENFORCED]` | **No** `[ENFORCED]` | `AUTHORIZATION_CONSUMED_UNINVOKED` (Qualified: provable only if external completeness verified; otherwise `[UNKNOWN]`) `[PROPOSED]` | **Yes** (new task proposal) | **Yes** (with fresh capability) | **Candidate Eligible** (Conditional on verified checkpoint integrity, store health, and completeness evidence; otherwise `Ineligible/Unknown`) | None |
| **B. Structural** | `TrustedExecutionBoundary` Executor Exception (`provenance.py:513-535`) | `status: "HALTED"`, `execution_status: "EXECUTION_FAILED"` `[ENFORCED & TESTED]` | **Yes** `[ENFORCED]` | **Yes** (Unknown) `[DOCUMENTED]` | `OUTCOME_UNKNOWN` / `PARTIAL` `[UNKNOWN]` | **Yes** (new task proposal) | **No** (Until Reconciled) | **Ineligible** (Until Reconciled) | **Yes** (External Reconciliation) |
| **B. Structural** | `TrustedExecutionBoundary` Interruption (`provenance.py:536-557`) | Re-raises `BaseException` `[ENFORCED & TESTED]` | **Yes** `[ENFORCED]` | **Yes** (Unknown) `[DOCUMENTED]` | `OUTCOME_UNKNOWN` / `PARTIAL` `[UNKNOWN]` | **Yes** (new task proposal) | **No** (Until Reconciled) | **Ineligible** (Until Reconciled) | **Yes** (External Reconciliation) |
| **B. Structural** | `TrustedExecutionBoundary` Evidence Failure (`provenance.py:559-590`) | `status: "HALTED"`, `execution_status: "UNVERIFIED_SUCCESS"` `[ENFORCED & TESTED]` | **Yes** `[ENFORCED]` | **Yes** (Finished) `[DOCUMENTED]` | `OUTCOME_UNKNOWN` `[DOCUMENTED]` | **Yes** (new task proposal) | **No** (Blind retry unsafe) | **Ineligible** (Until Reconciled) | **Yes** (External Reconciliation) |
| **B. Structural** | `TrustedExecutionBoundary` Terminal Success Write Failure (`provenance.py:606-616`) | `status: "ALLOWED"`, `execution_status: "EXECUTION_OUTCOME_UNKNOWN"` `[ENFORCED & TESTED]` | **Yes** `[ENFORCED]` | **Yes** (Finished) `[DOCUMENTED]` | `OUTCOME_UNKNOWN` `[DOCUMENTED]` | **Yes** (new task proposal) | **No** (Blind retry unsafe) | **Ineligible** (Until Reconciled) | **Yes** (External Reconciliation) |
| **C. Governance** | `AuthorizationAuthority.evaluate_and_issue_capability()` (`authorization.py:1931-1952`) | `status: "HALTED"`, `AUTHORIZATION_DENIED_...` `[ENFORCED & TESTED]` | No `[ENFORCED]` | No `[ENFORCED]` | `NOT_STARTED` `[PROPOSED]` | **No** (unless scope expanded) | **No** | **Ineligible** (Active denial blocks resume) | None |
| **C. Governance** | `CapabilityRegistry._check_denial_unlocked()` (`authorization.py:1508-1534`) | `status: "HALTED"`, `AUTHORIZATION_DENIED_DURABLE_DENIAL_ACTIVE...` `[ENFORCED & TESTED]` | No `[ENFORCED]` | No `[ENFORCED]` | `NOT_STARTED` `[PROPOSED]` | **No** (unless cleared by human) | **No** | **Ineligible** (Active denial blocks resume) | **Yes** (Administrative CLEAR_DENIAL) |
| **C. Governance** | `AuthorizationAuthority` Human Approval Escalation (`authorization.py:1963-1965`) | `status: "HALTED"`, `STOP_AND_ESCALATE_HUMAN_APPROVAL_REQUIRED` `[ENFORCED & TESTED]` | No `[ENFORCED]` | No `[ENFORCED]` | `NOT_STARTED` `[PROPOSED]` | **Yes** (with signed approval) | N/A (no exec attempt) | **Candidate Eligible** (suspension cleared with approval) | **Yes** (Human Authorization Approval) |
| **C. Governance** | `AuthorizationStore.consume_capability()` Replay / Stale Fence (`authorization.py:504-512`, `878-897`) | Replay error / Stale fence `[ENFORCED & TESTED]` | No (At boundary) `[ENFORCED]` | No `[ENFORCED]` | `NOT_STARTED` `[PROPOSED]` | **Yes** (new valid proposal) | **No** (Replaying dead token blocked) | **Ineligible** (Stale fence invalidates) | None |
| **C. Governance** | `EgressTransportBroker.establish_connection()` (`containment.py:882-957`) | Socket error: `Egress blocked: ...` `[ENFORCED & TESTED]` | Connection initiated | No payload sent `[ENFORCED]` | `NOT_STARTED` `[PROPOSED]` | **Yes** (use approved destination) | **No** | **Ineligible** | None |
| **C. Governance** | `ShowerCurtainEngine.transform_request()` (`engine.py:200-216`) | `status: "HALTED"` `[ENFORCED & TESTED]` | No `[ENFORCED]` | No `[ENFORCED]` | `NOT_STARTED` `[PROPOSED]` | **Yes** (sanitize credentials) | **No** | **Ineligible** | None |
| **C. Governance** | `LocalProvenanceStore` Pre-Dispatch Corruption (`provenance.py:202-230`) | `RuntimeError: Provenance log corruption detected` `[ENFORCED & TESTED]` | No `[ENFORCED]` | No `[ENFORCED]` | `NOT_STARTED` `[PROPOSED]` | **No** (log corrupt) | **No** | **Ineligible** | **Yes** (Audit Log Repair) |
| **C. Governance** | `CapabilityRegistry._check_poisoned()` (`authorization.py:1056-1060`) | `RuntimeError: CapabilityRegistry is in a poisoned state` `[ENFORCED & TESTED]` | No `[ENFORCED]` | No `[ENFORCED]` | `NOT_STARTED` `[PROPOSED]` | **No** (process poisoned) | **No** | **Ineligible** | **Yes** (Process Restart Required) |

### 11.2 Revised State Preservation Matrix

| State Category | Subsystem & Concrete Variables | Current Disposition on Halt | Survives Process Restart? | Actual Durability & Limitations | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Epistemic State** | `EntropyAwareScheduler`: `entropy_history`, `utility_history`, `history`, `total_cost`, `best_state`, `best_step`, `best_utility`. | **Retained in-memory temporarily** in `_schedulers[traj_id]`. **Discarded** upon subsequent submission under same trajectory ID via `reset_trajectory(traj_id)` (`core.py:475`). | **No** (In-memory Python objects). | Not a durable recovery mechanism. `best_state` is an unverified scalar optimization artifact. | `[ENFORCED]` |
| **Execution State** | `TrustedExecutionBoundary`: `_consumed_tokens`, `_consumed_attempts`, active closures, call arguments. | **Discarded / Lost**. Call closure finishes or terminates. Capability marked consumed. | Consumed tokens survive **only** if backed by `FileAuthorizationStore`. `_consumed_attempts` is in-memory only. | No workflow execution cursor or step progress tracker exists (**GAP-HALT-02**). | `[ENFORCED]` |
| **Authorization State (Capabilities)** | `Capability`: `token_id`, `fencing_token`, `scope_key`, `signature`, `expires_at`. | **Consumed or Expired**. If halt occurred before boundary, token expires unused. If at/after boundary, token is permanently consumed. | Consumed status survives if using `FileAuthorizationStore`. | Single-use tokens cannot be revived or un-consumed. | `[ENFORCED & TESTED]` |
| **Authorization State (Denials)** | `CapabilityRegistry`: `_denied_records`, `logs/denial_registry.jsonl`. | **Durably Persisted**. Active denials flushed and fsynced before memory mutation (`authorization.py:1184-1257`). | **Yes** (Append-only locked JSON-Lines log). | Downward restriction inheritance matches subpaths and action categories. Survives restarts. | `[ENFORCED & TESTED]` |
| **Authorization State (Approvals)** | `CapabilityRegistry`: `_consumed_approvals`. | **In-memory consumption set**. Durable only when recorded via `clear_denial_with_approval()`. | **No for ordinary actions**; **Yes for denial clearance**. | Multi-process deployments without shared storage risk cross-process ordinary approval replay (**GAP-HALT-03**). | `[ENFORCED]` |
| **Application State** | Caller inputs, `raw_payload`, `context`, `cpr`, intermediate LLM completions. | **Discarded**. Disposed when `process_submission()` returns. | **No**. | No application context checkpointing exists. | `[ENFORCED]` |
| **Derived State (Vectors)** | `VectorHygieneManager`: `_active_trajectories[traj_id]`. | **Best-effort cleanup attempt on ordinary exceptions**. `revoke_trajectory(traj_id)` pops tracking IDs and calls adapter `purge_vectors()`. | **No** (Quarantined vectors deleted from backend if purge succeeds; orphan if purge fails). | 1. `KeyboardInterrupt` / `BaseException` bypasses `except Exception` cleanup.<br>2. If backend purge fails, manager tracking IDs are already discarded (`GAP-HALT-07`). Cleanup is best-effort, not deterministic rollback. | `[ENFORCED & TESTED]` |
| **Evidence State** | `TamperEvidentAuditTrail` (`logs/epistemic_audit.jsonl`), `LocalProvenanceStore` (`logs/provenance_audit.jsonl`). | **Durably Persisted**. Append-only cryptographically chained JSON-Lines with `f.flush()` and `os.fsync()`. | **Yes**. | Chained hashes detect modification/corruption within surviving records. **Cannot detect valid suffix/tail truncation** without external tail anchor. | `[ENFORCED & TESTED]` |
| **External State** | Downstream HTTP endpoints, external databases, filesystems modified by executors. | **Indeterminate / Unmanaged**. EpistemicOS has no compensating transaction or rollback mechanism for tool side effects. | External system dependent. | High operational risk: in-flight failures leave external systems in unknown states. | `[ENFORCED]` |

---

## 12. Prioritized Gap Register

The register categorizes all identified gaps by priority and classification:

| Priority | Gap ID | Category | Description | Source References |
| :--- | :--- | :--- | :--- | :--- |
| **P0** | **GAP-HALT-06** | **Resolved (Phase 1)** | **Top-Level Status Ambiguity on `EXECUTION_OUTCOME_UNKNOWN`:** Remediated in `core.py`. When boundary returns `EXECUTION_OUTCOME_UNKNOWN`, orchestrator explicitly aborts `trajectory_scope` to prevent auto-commit on normal context-manager exit, no longer returns `ALLOWED`, revokes trajectory vectors, logs a pipeline `HALT` audit event, and returns top-level `"status": "RECONCILIATION_REQUIRED"` with `vector_cleanup` diagnostic breakdown. | `epistemicos/core.py`, `epistemicos/vector_hygiene.py` |
| **P1** | **GAP-HALT-07** | **Resolved (Phase 1)** | **Vector Backend Purge Failure with Tracking Reference Loss:** Remediated in `vector_hygiene.py`. `VectorHygieneManager` snapshots specific batches under lock without dropping concurrent stages, preserves failed purges in in-memory `_unpurged_vectors` dead-letter quarantine (observable via `get_unpurged_vectors()`), propagates explicit backend `False` returns, and provides retryable quarantine purging via `retry_quarantined_vectors()`. (Limitation: quarantine is process-local and in-memory; not durable across OS restarts). | `epistemicos/vector_hygiene.py` |
| **P1** | **GAP-HALT-01** | **Current Defect** | **`BaseException` Propagation Bypasses Pipeline Cleanup:** `core.py:651` catches `Exception` but not `BaseException`. When `TrustedExecutionBoundary` re-raises `BaseException` (`provenance.py:557`), the exception propagates out of the orchestrator to its caller without writing an audit halt event, leaving telemetry and pipeline cleanup incomplete. Furthermore, `VectorHygieneManager.trajectory_scope` catches `Exception`, bypassing vector revocation on `KeyboardInterrupt`. The process terminates only if the exception remains uncaught at the top-level application boundary. | `epistemicos/core.py:651-664`, `epistemicos/provenance.py:536-557`, `epistemicos/vector_hygiene.py:123-127` |
| **P1** | **GAP-HALT-04** | **Architectural Limit** | **Unmanaged Downstream Side Effects on In-Flight Crash:** If a tool callable mutates external state (e.g. database insert, file write) and subsequently crashes before returning, EpistemicOS records `EXECUTION_FAILED` but has no mechanism to query, compensate, or roll back the partial external mutation. | `epistemicos/provenance.py:513-535`, `epistemicos/tools.py:240-270` |
| **P2** | **GAP-HALT-08** | **Architectural Limit** | **Undetectable Suffix / Tail Truncation in Provenance Log:** `LocalProvenanceStore._inspect_health()` validates hash continuity among surviving lines in `logs/provenance_audit.jsonl`, but has no external tail anchor. If complete trailing records are deleted, the surviving prefix passes health checks, preventing the system from detecting lost historical events. | `epistemicos/provenance.py:232-273` |
| **P2** | **GAP-HALT-02** | **Architectural Limit** | **Lack of Execution Cursor & Workflow State Tracker:** EpistemicOS has no workflow cursor tracking multi-step agent trajectories. If an agent executes steps 1 and 2, then halts on step 3, there is no structured state to identify which steps are complete other than parsing unstructured provenance event logs. | `epistemicos/core.py:465-515` |
| **P2** | **GAP-HALT-03** | **Operational Limit** | **Unpersisted Ordinary Human Approval Consumption:** While denials and denial-clearances are durably persisted in `logs/denial_registry.jsonl`, ordinary capability consumption of human approvals (`_consumed_approvals`) is strictly in-memory in `InMemoryAuthorizationStore`. | `epistemicos/authorization.py:518-522`, `1040-1052` |
| **P3** | **GAP-HALT-05** | **Documented Limit** | **Process-Local Registry Poisoning Durability:** `_is_poisoned` in `CapabilityRegistry` is strictly an in-memory boolean. If persistence write and rollback both fail, the poisoned state does not persist across OS process restart unless unparseable JSON remains on disk. | `epistemicos/authorization.py:1020-1032`, `1056-1060` |

---

## 13. Deterministic Future Test Plan (Specification Only)

*Notice: These are formal test specifications for future implementation. No test files or production code are added in this work package.*

### Test Specifications

#### Test 1: Executor fails before external mutation; downstream confirms no side effect `[PROPOSED]`
- **Target Invariant:** When an executor crashes prior to external I/O, downstream state is clean, `EXECUTION_FAILED` is recorded, and the capability remains consumed.
- **Setup:** Register mock executor simulating pre-I/O crash. Provide mock downstream system verifying zero state changes.
- **Execution:** Invoke `execute_protected_action()`. Catch raised exception.
- **Assertions:** Assert `downstream.get_records() == []`, `store.get_events()[-1].event_type == "EXECUTION_FAILED"`, `authority.registry.is_consumed(token) is True`.

#### Test 2: Executor partially mutates external state before failing `[PROPOSED]`
- **Target Invariant:** An executor exception mid-mutation leaves external state partially modified; reconciler flags presence of `EXECUTION_FAILED` event (confirming control-plane termination) but external state is flagged as unmanaged; blind retry is blocked.
- **Setup:** Executor writes row 1 to downstream DB, then raises `RuntimeError("Network drop during row 2")`.
- **Execution:** Invoke `execute_protected_action()`. Catch error. Run `ProvenanceReconciler.reconcile_correlation()`.
- **Assertions:** Assert downstream DB contains row 1. Assert `reconciler.reconcile_correlation()` returns `valid: True, status: "RECONCILED"` for the control plane (because `EXECUTION_FAILED` terminal event exists), but external state is orphaned. Assert attempt to retry using same capability token is rejected with `CAPABILITY_VERIFICATION_FAILED_REPLAY_TOKEN_ALREADY_CONSUMED`.

#### Test 3: External operation succeeds but local terminal provenance write fails `[PROPOSED]`
- **Target Invariant:** When downstream execution succeeds but writing `EXECUTION_SUCCEEDED` throws, the boundary returns `EXECUTION_OUTCOME_UNKNOWN` with `recovery_required=True`.
- **Setup:** Mock `LocalProvenanceStore.record_event` to throw `OSError("Disk full")` only when `event_type == "EXECUTION_SUCCEEDED"`.
- **Execution:** Invoke `execute_protected_action()`.
- **Assertions:** Assert returned dictionary has `status: "EXECUTION_OUTCOME_UNKNOWN"`, `recovery_required: True`. Assert `core.py` (under proposed contract) returns `status: "RECONCILIATION_REQUIRED"` (rather than current `"status": "ALLOWED"`).

#### Test 4: External operation outcome cannot be queried `[PROPOSED]`
- **Target Invariant:** When downstream endpoint is unreachable during outcome query, operation remains quarantined in `OUTCOME_UNKNOWN`; automated retry is blocked.
- **Setup:** Downstream system is offline.
- **Execution:** Attempt recovery dispatch.
- **Assertions:** Boundary rejects dispatch with `OUTCOME_UNKNOWN_RETRY_PROHIBITED`.

#### Test 5: Reconciliation confirms successful completion; replay is prohibited `[PROPOSED]`
- **Target Invariant:** When external reconciliation confirms downstream success, the action is marked completed and subsequent execution attempts are rejected.
- **Setup:** Inject confirmed downstream transaction ID into reconciliation report.
- **Execution:** Attempt to execute the same operation payload.
- **Assertions:** Execution boundary rejects dispatch with `OPERATION_ALREADY_COMPLETED`.

#### Test 6: Reconciliation confirms no side effect; new attempt still requires fresh authorization `[PROPOSED]`
- **Target Invariant:** Proving that no downstream side effect occurred does not bypass authorization; a new attempt requires a fresh capability.
- **Setup:** Reconciliation confirms zero external mutations.
- **Execution:** Attempt execution with previous capability token.
- **Assertions:** Fails closed with `CAPABILITY_VERIFICATION_FAILED_REPLAY_TOKEN_ALREADY_CONSUMED`. New attempt succeeds only when fresh capability is evaluated and issued.

#### Test 7: Denial clearance does not revive an old capability or checkpoint `[PROPOSED]`
- **Target Invariant:** Invoking `clear_denial_with_approval()` unblocks future policy checks but does not re-activate an old capability or checkpoint.
- **Setup:** Record denial. Obtain signed `CLEAR_DENIAL` approval. Clear denial.
- **Execution:** Attempt to execute using capability token issued prior to the denial.
- **Assertions:** Rejection with `CAPABILITY_VERIFICATION_FAILED_REVOKED_TOKEN` or `ALREADY_CONSUMED`.

#### Test 8: Old checkpoint rejected after policy change `[PROPOSED]`
- **Target Invariant:** A candidate checkpoint captured under Policy v1 is rejected if the active authority policy digest has changed.
- **Setup:** Mint checkpoint with `policy_digest = hash(Policy_v1)`. Update authority to Policy v2.
- **Execution:** Submit checkpoint for resumption.
- **Assertions:** Resumption rejected with `POLICY_DRIFT_DETECTED`.

#### Test 9: Old checkpoint rejected after fencing generation advances `[PROPOSED]`
- **Target Invariant:** If a scope's fencing generation advances, earlier checkpoints for that scope are rejected as stale.
- **Setup:** Mint checkpoint recording scope generation 1. Allocate scope generation 2 in `AuthorizationStore`.
- **Execution:** Submit checkpoint for resumption.
- **Assertions:** Resumption rejected with `STALE_FENCING_GENERATION_OBSERVED`.

#### Test 10: Scheduler state reset on new submission `[PROPOSED]`
- **Target Invariant:** Calling `process_submission()` clears existing trajectory scheduler instances in `_schedulers[traj_id]`.
- **Setup:** Populate `_schedulers["traj_1"]` with 5 steps of history and high utility `best_state`.
- **Execution:** Call `process_submission(..., trajectory_id="traj_1")`.
- **Assertions:** Assert `_schedulers["traj_1"]` step count is reset to 0; initial entropy is recalculated; prior `best_state` is discarded.

#### Test 11: Checkpoint cannot restore consumed authorization `[PROPOSED]`
- **Target Invariant:** A checkpoint containing a previously executed step's token ID cannot use that token ID to execute step 2.
- **Setup:** Mint mock checkpoint containing consumed token ID.
- **Execution:** Attempt boundary dispatch using checkpoint's token.
- **Assertions:** Boundary rejects with `TOKEN_ALREADY_CONSUMED`.

#### Test 12: Concurrent checkpoint consumption with process interruption at persistence boundary `[PROPOSED]`
- **Target Invariant:** Two processes concurrently attempting to resume the same checkpoint result in exactly one execution, even under simulated process interruption.
- **Setup:** Two worker processes acquire flock on checkpoint file. Worker 1 consumes token and simulates interrupt. Worker 2 attempts resumption.
- **Assertions:** Exactly one worker marks consumed. Worker 2 receives `CHECKPOINT_ALREADY_CONSUMED`.

#### Test 13A: Python-Level Interruption (`KeyboardInterrupt`) `[PROPOSED]`
- **Target Invariant:** A Python-level `KeyboardInterrupt` raised within an in-flight executor writes `EXECUTION_INTERRUPTED` provenance event and propagates out without being swallowed by orchestrator.
- **Setup:** Executor raises `KeyboardInterrupt` during execution.
- **Execution:** Run through `execute_protected_action()` wrapped in orchestrator.
- **Assertions:** Assert `LocalProvenanceStore` contains `EXECUTION_INTERRUPTED` event with `reason: "KeyboardInterrupt"`. Assert `KeyboardInterrupt` bubbles to caller. Assert capability token remains consumed. Assert `ResourceProfiler.__exit__` executed. Assert vector revocation was bypassed in `trajectory_scope`.

#### Test 13B: Operating-System Default Signal Delivery (`SIGTERM`) `[PROPOSED]`
- **Target Invariant:** A default OS-level `SIGTERM` delivered to a child worker process terminates the process abruptly; in Python POSIX inspects `Popen.returncode == -15` (or shell exit status 143 where $128 + 15$).
- **Setup:** Spawn worker subprocess executing protected action with barrier synchronization. Deliver default `signal.SIGTERM` during active window.
- **Execution:** Subprocess terminates via default OS signal disposition (no graceful handler installed).
- **Assertions:** Assert `proc.poll() == -15` when inspecting Python `Popen.returncode` directly (or exit code 143 if inspected through shell `$?`). Inspect `LocalProvenanceStore` on disk: assert `EXECUTION_STARTED` exists, but terminal event is missing. Assert downstream side effects are classified as `OUTCOME_UNKNOWN`.

#### Test 13C: Operating-System Signal Delivery with Test-Harness Graceful Handler `[PROPOSED]`
- **Target Invariant:** When a test harness explicitly installs a graceful `SIGTERM` handler (`signal.signal(signal.SIGTERM, handler)`), the worker intercepts the signal, attempts best-effort recording of `EXECUTION_INTERRUPTED`, and terminates with controlled exit code.
- **Setup:** Worker subprocess registers explicit `SIGTERM` handler. Deliver `SIGTERM` mid-call.
- **Execution:** Handler intercepts signal, writes `EXECUTION_INTERRUPTED` to provenance store, and exits with code 143.
- **Assertions:** Assert `proc.poll() == 143`. Inspect `LocalProvenanceStore`: assert `EXECUTION_INTERRUPTED` exists. Assert downstream state is treated as `OUTCOME_UNKNOWN` until external reconciliation proves whether the callable was interrupted mid-mutation.

#### Test 13D: Uncatchable Process Termination (`SIGKILL`) `[PROPOSED]`
- **Target Invariant:** An immediate uncatchable process termination (`SIGKILL`) leaves the operation in `OUTCOME_UNKNOWN` on restart; no cleanup executes; reconciler flags missing terminal event.
- **Setup:** Spawn worker subprocess executing protected action. Deliver `signal.SIGKILL` mid-call.
- **Execution:** Process dies instantly. No Python exception or signal handler runs.
- **Assertions:** Assert `proc.poll() == -9` when inspecting Python `Popen.returncode` directly (or exit code 137 where $128 + 9$ if inspected through shell). Inspect provenance log on disk: assert `EXECUTION_STARTED` exists, but no terminal event exists. Run `ProvenanceReconciler`: assert `status: "INCOMPLETE_EVIDENCE"`, `violations` includes missing terminal outcome event. Assert automatic retry is blocked.

#### Test 13E: Storage Fault Injection & Torn Journal Line `[PROPOSED]`
- **Target Invariant:** Simulated abrupt storage write truncation or write failure mid-record leaves torn JSON lines, causing fail-closed rejection upon restart.
- **Setup:** Write valid event records, followed by a half-written torn JSON line simulating sudden process crash or I/O failure.
- **Execution:** Instantiate `LocalProvenanceStore`. Call `record_event()`.
- **Assertions:** `_inspect_health()` returns `healthy == False`; `record_event()` fails closed with `RuntimeError("Provenance log corruption detected")`. (Distinct from uncontrolled hardware power loss, which involves non-volatile cache synchronization).

#### Test 15: Valid Trailing-Record Deletion / Suffix Truncation Detection `[PROPOSED]`
- **Target Invariant:** Evaluates whether `LocalProvenanceStore._inspect_health()` can detect deletion of one or more valid trailing records from the log.
- **Setup:** Generate a valid provenance log with 5 sequential events ($E_1, E_2, E_3, E_4, E_5$) chained from `GENESIS_SEED`.
- **Execution:** Delete the last 2 records ($E_4, E_5$) from disk, leaving $E_1, E_2, E_3$ completely intact. Reinitialize `LocalProvenanceStore` and call `_inspect_health()`.
- **Assertions:** In the current implementation without external tail anchoring, `_inspect_health()` returns `healthy == True, count == 3`, failing to detect that $E_4$ and $E_5$ were deleted (`GAP-HALT-08`). Under proposed architecture with external tail anchoring, the check must fail with `PROVENANCE_SUFFIX_TRUNCATION_DETECTED`.

#### Test 16: Vector Backend Purge Failure with Tracking Loss (`GAP-HALT-07`) `[PROPOSED]`
- **Target Invariant:** When `VectorStoreAdapter.purge_vectors()` fails on backend deletion, `VectorHygieneManager.revoke_trajectory()` must not silently discard tracking references while reporting vectors as revoked.
- **Setup:** Stage vector IDs `[101, 102]` into `VectorHygieneManager`. Configure mock vector backend client whose purge method raises `ConnectionError("Pinecone unreachable")`.
- **Execution:** Trigger ordinary exception inside `trajectory_scope` (or call `revoke_trajectory("traj_1")` directly).
- **Assertions:** Under current code, `revoke_trajectory()` logs an error, returns `[101, 102]`, but `get_staged_count("traj_1")` drops to 0 (`GAP-HALT-07`). Under proposed remediation, `revoke_trajectory()` must retain failed IDs in a quarantine/dead-letter set (`_unpurged_vectors`) and return `success == False`.

#### Test 14: Top-level response never reports successful completion for unknown execution outcome `[PROPOSED]`
- **Target Invariant:** An execution ending in `EXECUTION_OUTCOME_UNKNOWN` never returns `"status": "ALLOWED"`.
- **Setup:** Executor succeeds but provenance store throws on success event.
- **Execution:** Call `orchestrator.process_submission()`.
- **Assertions:** Assert `res["status"] != "ALLOWED"`, `res["execution_status"] == "EXECUTION_OUTCOME_UNKNOWN"`, `res["status"] == "RECONCILIATION_REQUIRED"`.

---

## 14. Audit Conclusion & Remaining Unresolved Questions

EpistemicOS demonstrates rigorous pre-execution gate interception, cryptographic audit chaining, best-effort vector hygiene cleanup invocation on covered ordinary-exception paths (subject to backend adapter success), and authoritative atomic capability consumption.

However, controlled resumability cannot be safely enabled until:
1. **GAP-HALT-01** (handling `BaseException` without swallowing process control, and ensuring vector hygiene cleans up on interrupt) is corrected.
2. **GAP-HALT-08** (absence of external tail anchoring permitting undetectable suffix deletion) is addressed via an external trust anchor or high-water sequence register.
3. Multi-scope fencing and non-authority checkpointing contracts are formally implemented.
4. Downstream executors provide authoritative state query and reconciliation hooks.

*(Note: **GAP-HALT-06** and **GAP-HALT-07** have been remediated in Phase 1 with deterministic tests).*

### Remaining Unresolved Questions for Stakeholder Decision
1. **Downstream Idempotency & Compensating Action Protocol:** When an executor crashes in `OUTCOME_UNKNOWN` status, should EpistemicOS mandate that tool wrappers implement an `idempotency_key` protocol, or should it require a registered `reconcile_status()` callback on tools?
2. **Multi-Scope Checkpoint Boundary:** When a multi-step workflow interacts with multiple external systems across different fencing scopes, should a failure in any single scope abort the entire checkpoint or support partial rollbacks?
3. **Top-Level Status Breaking Change:** Phase 1 remediation of `GAP-HALT-06` returns top-level `"status": "RECONCILIATION_REQUIRED"` when execution outcome is unknown. Are all external consumers prepared to ingest this status?

**Final Recommendation:** With Phase 1 remediation completed, `EXECUTION_OUTCOME_UNKNOWN` fails closed with `RECONCILIATION_REQUIRED` and vector quarantine tracking references are preserved in memory. However, controlled resumability and automated recovery must remain prohibited until process-level interruption (`GAP-HALT-01`) and external ledger anchoring (`GAP-HALT-08`) are addressed.
