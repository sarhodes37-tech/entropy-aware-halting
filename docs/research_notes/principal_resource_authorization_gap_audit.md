# EpistemicOS Security Audit: Principal Binding & Resource Authorization Gap Analysis

**Date:** March 2026
**Auditor:** Jules Security Subsystem
**Scope:** Existing authorization, trusted tool execution, resource targeting, and Observatory HTTP exposure.
**Threat Model Reference:** CVE-2026-118539 (Drupal Commerce Core access-control bypass via decoupled principal, missing object ownership, and unverified execution context).
**Status:** READ-ONLY Security Audit — Architecture & Implementation Gap Analysis.

---

## 1. Executive Summary

### 1.1 Overall Security Assessment
EpistemicOS has implemented sophisticated and mathematically rigorous defense-in-depth mechanisms for governance gates, cryptographic provenance logging (`TamperEvidentAuditTrail`, `LocalProvenanceStore`), single-use capability issuance with HMAC signatures, interprocess replay protection, monotonic fencing tokens (`canonicalize_fencing_scope`), and zero-side-effect execution boundaries (`TrustedExecutionBoundary`).

However, an audit of the authorization call-paths against the access-control threat model exposed by **CVE-2026-118539** reveals critical architectural gaps where authorization decisions decouple from authenticated principals, object-level ownership boundaries, and fine-grained field mutations:

1. **Decoupled Principal Identity at the Execution Boundary:** While `CapabilityRegistry.sign_capability()` cryptographically signs `principal_id` into the issued token and `AuthorizationAuthority.verify_capability()` supports principal verification, `TrustedExecutionBoundary.execute_protected_action()` **completely omits passing `principal_id`** to `verify_capability()`. Furthermore, `ExecutionContext` does not track or store `principal_id`. Consequently, any caller presenting a valid token ID, matching target, and request digest can execute an action regardless of whether the executing principal matches the authorized principal.
2. **Caller-Controlled Principal Ingress:** At tool ingress (`epistemicos/tools.py`) and pipeline orchestration (`epistemicos/core.py`), `principal_id` is derived from untrusted, caller-controlled dictionary payloads (`context.get("principal_id")` or `context.get("requestor_id")`) with fallback to `"agent_default"`. There is no authenticated security context or cryptographic identity provider binding the caller to their claimed principal ID.
3. **Absence of Object-Level and Multi-Tenant Authorization:** Policy evaluation (`Policy.is_target_allowed()` and `TrustedTaskContract.is_action_permitted()`) operates entirely on coarse URI/string path allowlists and wildcard sets. The system possesses no model of object ownership, tenant partitioning, or relational access control. A principal authorized for `read_table` or `update` on a resource can access or mutate any object belonging to any tenant residing on that resource.
4. **Fragile and Ambiguous Target Extraction:** `TrustedToolWrapper._extract_actual_target()` uses a fallthrough heuristic that defaults to the first positional string argument or tool default target. If an agent supplies a note, comment, or extraneous string parameter as the first positional argument to a tool, that arbitrary string is treated as the authorized resource target, decoupling authorization from the actual object operated upon by the executor.
5. **No Field-Level Authorization:** Authorization is strictly binary per `(action_name, target)` tuple. Once an action is authorized, downstream tool executors receive unconstrained parameters and can mutate protected, financial, administrative, or identity fields without boundary inspection.
6. **Unauthenticated Read-Only Observatory API Exposure:** The Observatory HTTP server (`epistemicos/ui/server.py`) exposes five REST endpoints returning detailed execution traces, provenance event streams, cryptographic digests, capability token IDs, and system health. These endpoints require zero authentication or authorization. When run with `--host 0.0.0.0`, all sensitive internal execution metadata is exposed to the local network or internet.

### 1.2 Existing Controls Addressing the Threat Model
The audit confirms that EpistemicOS already incorporates several robust controls:
- **Canonical Request Digest Binding:** Payloads cannot be altered between capability issuance and execution; `TrustedExecutionBoundary` recomputes the SHA-256 canonical digest and enforces exact equality (`current_digest == auth_digest`).
- **Callable Identity & Object Identity Enforcement (Option A):** An issued capability cannot be executed by an arbitrary function. `execute_protected_action()` validates that `executor_func` matches the exact callable object registered in `executor_registry` (`executor_func is bound_callable`).
- **Atomic Single-Use Replay Protection:** Tokens cannot be reused. `AuthorizationStore.consume_capability()` provides linearization point guarantees under file locking (`fcntl.flock`) and journal persistence.
- **Monotonic Fencing Tokens:** Stale or out-of-order execution attempts across distributed or multithreaded tasks are rejected via monotonic scope generations.
- **Tamper-Evident Provenance Logging:** All execution attempts (`EXECUTION_STARTED`, `EXECUTION_SUCCEEDED`, `EXECUTION_FAILED`) and governance decisions are logged to an append-only cryptographic hash chain.

### 1.3 Most Consequential Remaining Gaps
1. **Critical:** Inability of `TrustedExecutionBoundary` to verify principal identity against presented capabilities (`principal_id` omitted in `execute_protected_action`).
2. **High:** Unauthenticated, spoofable `principal_id` accepted from caller context dicts at tool and orchestrator ingress.
3. **High:** Target extraction ambiguity in `TrustedToolWrapper._extract_actual_target()` allowing non-resource positional strings to masquerade as targets.
4. **Medium-High:** Lack of object-level, tenant-level, and ownership-based authorization in `Policy` and `TrustedTaskContract`.
5. **Medium:** Absence of field-level access control on tool inputs and model payloads.
6. **Medium:** Unauthenticated Observatory HTTP API exposing authorization metadata, trace histories, and token identifiers.

---

## 2. Architecture and Execution-Path Diagrams

### 2.1 Complete Principal and Authorization Lifecycle

```
[Untrusted Agent / Client Invocation]
        |
        |  1. Invokes tool(args, kwargs, context={"principal_id": "alice", "task_id": "T1"})
        v
[TrustedToolWrapper.__call__] (epistemicos/tools.py:146)
        |
        |-- 2. _extract_actual_target(args, kwargs)  <--- [GAP: Heuristic extraction, positional fallback]
        |-- 3. principal_id = context.get("principal_id", "agent_default") <--- [GAP: Caller-controlled spoofing]
        |-- 4. payload_digest = compute_canonical_digest(raw_payload)
        v
[AuthorizationAuthority.evaluate_and_issue_capability] (epistemicos/authorization.py:2050)
        |
        |-- 5. Check Durable Denial Registry (_check_denial_unlocked)
        |-- 6. Verify TrustedTaskContract signature & scope (if present)
        |-- 7. Policy.is_principal_allowed(principal_id) <--- [Checks allowlist, defaults to {"*"}]
        |-- 8. Policy.is_operation_allowed(action_name)
        |-- 9. Policy.is_target_allowed(target)         <--- [Coarse string match only; no object ownership]
        |-- 10. Human approval verification & replay check (if required)
        |-- 11. Allocate monotonic fencing token & sign Capability
        |       Payload: token_id:principal_id:corr_id:req_id:action:target:digest:exec_id:policy_ver:...
        v
[Capability Issued: Token 'AUTH-CAP-...'] (Contains principal_id="alice", fencing_token=N)
        |
        |  12. Wraps into ExecutionContext(token_id, digest, corr_id, req_id, ...)
        |      *** NOTE: ExecutionContext does NOT contain principal_id! ***
        v
[TrustedExecutionBoundary.execute_protected_action] (epistemicos/provenance.py:341)
        |
        |-- 13. Recompute canonical digest: current_digest == auth_digest? (OK)
        |-- 14. Resolve executor_id = get_callable_identity(executor_func)
        |-- 15. Call authority.verify_capability(...) (provenance.py:396-405)
        |       [CRITICAL GAP]: verify_capability() is called WITHOUT principal_id!
        |       (principal_id defaults to None; verification of principal is BYPASSED)
        |-- 16. Option A check: executor_func is bound_callable? (OK)
        |-- 17. Atomic token consumption: registry.consume_token(token_id) (OK)
        |-- 18. Emit EXECUTION_STARTED provenance event
        v
[Executor Callable Execution]
        |
        |  19. executor_func(*args, **call_kwargs)
        |      [GAP: Downstream executor executes directly in host runtime;
        |            no field-level gating; no object ownership check;
        |            can access Bob's data or mutate financial fields]
        v
[Outcome Verification & Provenance]
        |-- 20. Check required_success_evidence (if contract requires it)
        |-- 21. Emit EXECUTION_SUCCEEDED / EXECUTION_FAILED provenance event
        v
[Return Result to Caller]
```

### 2.2 Trace Comparison: Intended Security Guarantee vs. Actual Code Path

| Property | Designed / Assumed Control | Actual Code Implementation | Status |
| :--- | :--- | :--- | :--- |
| **Principal Origin** | Authenticated Identity Token / Certificate | `context.get("principal_id", "agent_default")` (`tools.py:179`, `core.py:575`) | **Caller-Controlled** |
| **Principal Capability Binding** | Cryptographically signed in token | `CapabilityRegistry.sign_capability` binds `principal_id` (`authorization.py:1181`) | **Enforced at Issuance** |
| **Principal Verification at Boundary** | Execution boundary ensures caller matches token principal | `execute_protected_action` does not pass `principal_id` to `verify_capability` (`provenance.py:396`) | **Bypassed / Missing** |
| **Target Extraction** | Precise, unforgeable resource identity | Heuristic scan in kwargs, then first positional string, then default (`tools.py:118-142`) | **Ambiguous / Spoofable** |
| **Resource vs Object Auth** | Fine-grained object ownership & tenant isolation | String exact/wildcard match in `Policy.allowed_resources` (`authorization.py:273`) | **Coarse Resource Only** |
| **Field-Level Auth** | Differentiates read/write of sensitive vs standard fields | None; raw arguments forwarded to executor without inspection (`provenance.py:465`) | **Absent** |
| **Observatory Access** | Secure monitoring for authorized operators | Public unauthenticated GET endpoints on all routes (`server.py:65`) | **Unauthenticated** |

---

## 3. Findings Register

### SEC-01: Execution Boundary Fails to Verify Principal Identity on Presented Capability
- **ID:** SEC-01
- **Severity:** Critical
- **Component:** `epistemicos/provenance.py` (`TrustedExecutionBoundary.execute_protected_action`), lines 396–405; `epistemicos/authorization.py` (`AuthorizationAuthority.verify_capability`), lines 2051, 2107–2108.
- **Finding:** While `AuthorizationAuthority.verify_capability()` has logic to reject principal mismatches (`if principal_id is not None and cap.principal_id != principal_id`), `TrustedExecutionBoundary.execute_protected_action()` **does not pass `principal_id`** when calling `verify_capability()`. Furthermore, `ExecutionContext` (lines 80–100) does not even define or store a `principal_id` field.
- **Evidence:**
  - `epistemicos/provenance.py:396-405`:
    ```python
    valid, cap_reason, cap = self.authority.verify_capability(
        token_id=auth_token_id,
        action_name=action_name,
        target=target,
        canonical_request_digest=current_digest,
        executor_id=executor_id,
        correlation_id=corr_id,
        request_id=req_id,
        policy_version=pol_version
    )
    ```
  - In `epistemicos/authorization.py:2051`, `principal_id: Optional[str] = None`. Since it is omitted by `execute_protected_action()`, `principal_id` is `None` and line 2107 (`if principal_id is not None...`) is never evaluated.
- **Exploit Preconditions:** An attacker operating within an agent session or workflow acquires or intercepts an issued `token_id` (e.g. from an unauthenticated Observatory trace, log, or concurrent task).
- **Impact:** An unauthorized principal can present a capability token issued to a privileged principal and execute protected operations through the execution boundary without triggering a principal mismatch rejection.
- **Existing Mitigation:** The attacker must present matching `action_name`, `target`, `canonical_request_digest`, and a registered `executor_func`. However, within identical tool calls, request digests are identical.
- **Confidence:** Confirmed.
- **Recommendation:** Add `principal_id: str` to `ExecutionContext`. Update `TrustedExecutionBoundary.execute_protected_action()` to accept and pass `principal_id` to `self.authority.verify_capability()`. Fails closed if `principal_id` is missing or mismatched.

---

### SEC-02: Principal Identity Derived from Untrusted Caller Context at Ingress
- **ID:** SEC-02
- **Severity:** High
- **Component:** `epistemicos/tools.py` (`TrustedToolWrapper.__call__`), line 179; `epistemicos/core.py` (`EpistemicOrchestrator._execute_pipeline`), line 575.
- **Finding:** At both tool wrapper ingress and orchestrator pipeline execution, `principal_id` is extracted directly from the unverified caller-supplied dictionary:
  `principal_id = exec_context.get("principal_id", "agent_default")` in `tools.py:179` and
  `principal_id = context.get("requestor_id", "agent_default")` in `core.py:575`.
- **Evidence:**
  - `epistemicos/tools.py:174, 179`:
    ```python
    exec_context = dict(context or {})
    ...
    # Principal ID must strictly originate from verified context or default
    principal_id = exec_context.get("principal_id", "agent_default")
    ```
    Despite the comment stating "must strictly originate from verified context", no verification of `context` or cryptographic authentication of the caller is performed.
  - `epistemicos/core.py:575`:
    ```python
    principal_id=context.get("requestor_id", "agent_default"),
    ```
- **Exploit Preconditions:** Any untrusted caller invoking a tool wrapper or passing a payload to the orchestrator can supply `context={"principal_id": "admin_principal"}`.
- **Impact:** Complete spoofing of principal identity prior to policy evaluation. If a policy permits operation `admin_action` only to `allowed_principals={"admin_principal"}`, an untrusted agent simply sets `"principal_id": "admin_principal"` in `context` to obtain an authorized capability.
- **Existing Mitigation:** `Policy.allowed_principals` can restrict which principals are authorized, but because the principal identity itself is unauthenticated, allowlists are completely ineffective against spoofing.
- **Confidence:** Confirmed.
- **Recommendation:** Require `principal_id` to be bound to a cryptographically verified session token, mutual TLS cert, or authenticated context object rather than an arbitrary mutable dictionary key.

---

### SEC-03: Ambiguous and Fragile Resource Target Extraction in Tool Wrappers
- **ID:** SEC-03
- **Severity:** High
- **Component:** `epistemicos/tools.py` (`TrustedToolWrapper._extract_actual_target`), lines 73–144.
- **Finding:** The fallback sequence in `_extract_actual_target` falls through to the first positional string argument (`if args and isinstance(args[0], str)`) or a static `default_target`. When tools accept non-target string arguments (such as human notes, audit reasons, descriptions, or messages) before or in place of resource targets, the wrong string is evaluated for authorization.
- **Evidence:**
  - `epistemicos/tools.py:136-143`:
    ```python
    # 5. First positional string argument if positional args provided
    if args and isinstance(args[0], str) and args[0].strip():
        return args[0].strip()

    # 6. Default target configured at tool registration
    if self.default_target:
        return self.default_target
    ```
  - Empirical verification: For a tool `def transfer(note: str, account_id: str, amount: float)`, calling `tool("payment for coffee", "ACC-999", 50.0)` extracts `"payment for coffee"` as the target resource.
- **Exploit Preconditions:** A registered tool with positional parameters or a default target where the actual consequential resource is a secondary argument or keyword argument.
- **Impact:** Target Confusion Attack: An attacker supplies a benign allowed target string as the first argument (e.g. `"benign_log"` or `"/tmp/test"`), causing `Policy.is_target_allowed()` and `_extract_actual_target()` to authorize the call. Meanwhile, the underlying executor acts upon a sensitive target passed in another parameter.
- **Existing Mitigation:** If `target_param` or `target_extractor` is explicitly registered, those take precedence over positional inference. However, registration does not mandate them.
- **Confidence:** Confirmed.
- **Recommendation:** Deprecate positional argument fallback and static `default_target` for mutating operations. Require explicit parameter binding via signature inspection (`target_param`) or custom extractors (`target_extractor`). Fail closed if the resolved target does not map to a recognized, typed resource identifier.

---

### SEC-04: Lack of Object-Level Authorization, Ownership Binding, and Tenant Isolation
- **ID:** SEC-04
- **Severity:** High
- **Component:** `epistemicos/authorization.py` (`Policy`, lines 240–288; `TrustedTaskContract`, lines 145–225); `epistemicos/action_policy.py` (`ActionRegistry`, lines 56–180).
- **Finding:** The authorization model implements coarse resource-level allowlisting (`allowed_resources: Set[str]`), but lacks any concept of:
  1. Object-level identity (distinguishing `/database/orders/123` from `/database/orders/456` when wildcards are used).
  2. Principal-to-object ownership (whether principal $P$ owns or is a member of object $O$).
  3. Tenant or organizational boundaries.
- **Evidence:**
  - `epistemicos/authorization.py:273-279`:
    ```python
    def is_target_allowed(self, target: str) -> bool:
        if not self.allowed_resources:
            return False
        if "*" in self.allowed_resources:
            return True
        return target in self.allowed_resources
    ```
  - Neither `Policy` nor `Capability` nor `TrustedTaskContract` stores an `owner_id`, `tenant_id`, or ACL predicate.
- **Exploit Preconditions:** A multi-tenant or multi-user environment where two principals are authorized for the same tool or resource endpoint (e.g. `order_update` on `/api/orders/*`).
- **Impact:** A direct equivalent of **CVE-2026-118539**: An authenticated principal authorized to update *their own* orders or profiles can update *any other user's or tenant's* orders or profiles simply by substituting the object ID.
- **Existing Mitigation:** None at the EpistemicOS control plane layer. Relies entirely on downstream applications to enforce object ownership.
- **Confidence:** Confirmed.
- **Recommendation:** Introduce object-level contextual evaluation in `Policy` and `TrustedTaskContract`, allowing policies to define ownership assertions (e.g. `target_owner_evaluator(principal_id, target, payload) -> bool`) or tenant boundary matching (`tenant_id`).

---

### SEC-05: Absence of Field-Level Authorization for Read and Mutation Operations
- **ID:** SEC-05
- **Severity:** Medium
- **Component:** `epistemicos/models.py` (`CanonicalProblemRepresentation.SENSITIVE_FIELDS`), lines 420–445; `epistemicos/provenance.py` (`TrustedExecutionBoundary.execute_protected_action`), lines 460–475.
- **Finding:** EpistemicOS does not possess a mechanism to enforce field-level permissions. While `CanonicalProblemRepresentation` defines `SENSITIVE_FIELDS` (`ssn`, `account_number`, `banking_routing`, `account_balance_usd`, `proprietary_cargo`), this set is utilized **exclusively for audit log masking and egress sanitization**, never for authorization gating.
- **Evidence:**
  - `epistemicos/core.py:240-252`: `sensitive_fields` are stripped only from audit log snippets and CPR masks.
  - In `epistemicos/provenance.py:465`, `executor_func()` is called with whatever `raw_payload` arguments were supplied. There is no filter or check against protected fields.
- **Exploit Preconditions:** A tool that updates an object containing both ordinary mutable fields (e.g. `display_name`, `bio`) and protected/privileged fields (e.g. `role`, `is_admin`, `balance`, `owner_id`).
- **Impact:** Mass-Assignment / Unauthorized Field Mutation: An authorized user invoking an `update_user` tool can submit `{"role": "superuser", "balance": 999999}` alongside their profile change. EpistemicOS will issue an affirmative capability and execute the modification without objection.
- **Existing Mitigation:** None at the middleware boundary.
- **Confidence:** Confirmed.
- **Recommendation:** Implement field-level mutation contracts in `Policy` and `TrustedTaskContract` specifying `permitted_fields` and `prohibited_fields` for state-mutating actions. Validate payload keys in `TrustedExecutionBoundary` before dispatching to `executor_func`.

---

### SEC-06: Unauthenticated HTTP API Exposure in Observatory Server
- **ID:** SEC-06
- **Severity:** Medium
- **Component:** `epistemicos/ui/server.py` (`ObservatoryRequestHandler.do_GET`, lines 50–70; `_handle_api_route`, lines 95–130); `epistemicos/ui/adapters.py` (`ObservatoryDataAdapter`), lines 40–180.
- **Finding:** The Observatory HTTP server exposes five API endpoints:
  - `/api/overview`
  - `/api/traces`
  - `/api/trace/<id>`
  - `/api/provenance`
  - `/api/benchmarks`
  None of these routes require authentication, API keys, or session cookies. They return unredacted execution traces, action names, target endpoints, request digests, gate decisions, and full capability tokens (`authorization_token_id`).
- **Evidence:**
  - `epistemicos/ui/server.py:65`:
    ```python
    # Route API requests
    if path.startswith("/api/"):
        self._handle_api_route(path)
        return
    ```
    No authentication check exists before calling `_handle_api_route`.
  - `epistemicos/ui/server.py:215`:
    ```python
    parser.add_argument("--host", default="127.0.0.1", help="Binding host (default: 127.0.0.1)")
    ```
    The server allows binding to `0.0.0.0` or public IPs via CLI parameters.
- **Exploit Preconditions:** Observatory server started and exposed on a network interface reachable by an attacker.
- **Impact:** Reconnaissance & Token Harvesting: An attacker reads active authorization tokens (`AUTH-CAP-...`), correlation IDs, request digests, and internal target topologies, enabling token reuse (SEC-01) and system mapping.
- **Existing Mitigation:** Bound by default to localhost (`127.0.0.1`). Strict GET-only enforcement (POST/PUT/DELETE blocked).
- **Confidence:** Confirmed.
- **Recommendation:** Implement Bearer token authentication or mTLS for all `/api/*` endpoints. Redact active `authorization_token_id` values from trace responses. Warn or reject non-loopback binding (`--host 0.0.0.0`) unless an authentication secret is explicitly configured.

---

### SEC-07: In-Process Tool Executor Direct Invocation Bypass
- **ID:** SEC-07
- **Severity:** Low-Medium
- **Component:** `epistemicos/tools.py` (`TrustedToolWrapper._executor_func`), line 48.
- **Finding:** `TrustedToolWrapper` encapsulates the raw executable callable as a protected attribute `self._executor_func`. Within the same Python runtime process, any agent component or third-party dependency holding a reference to `TrustedToolWrapper` can bypass `__call__()` and execute `wrapper._executor_func(*args, **kwargs)` directly.
- **Evidence:**
  - `epistemicos/tools.py:48`: `self._executor_func = executor_func`.
  - Calling `tool._executor_func()` executes the underlying operation with zero gate evaluation, zero capability issuance, and zero provenance logging.
- **Exploit Preconditions:** Untrusted code running in the same Python process as EpistemicOS with direct object reference to the tool wrapper.
- **Impact:** Complete bypass of EpistemicOS control plane and audit trail.
- **Existing Mitigation:** The public `.executor_func` property was removed in previous hardening, and `ExecutorRegistry` prevents dictionary enumeration. However, standard Python attribute access (`._executor_func`) remains accessible.
- **Confidence:** Confirmed.
- **Recommendation:** Document the process boundary limitation. Where process isolation is required, tool executors should be hosted in isolated subprocesses, containers, or RPC workers communicating via authenticated IPC rather than in-process closures.

---

## 4. Existing Control Coverage Matrix

The following matrix maps the 11 threat categories derived from CVE-2026-118539 and modern agentic security risks across EpistemicOS production code and test suites.

| Threat Category | Production Enforcement Status | Existing Test Coverage | Test Classification | Primary Evidence & File Paths |
| :--- | :--- | :--- | :--- | :--- |
| **1. Principal Spoofing / Ingress** | **UNENFORCED** (Caller context trusted) | `tests/unit/test_phase1_authorization.py:762` | **PARTIAL** | Policy tests verify empty principals fail closed; zero tests verify ingress authenticity. `tools.py:179` accepts any `principal_id`. |
| **2. Cross-Principal Capability Reuse** | **UNENFORCED** at Execution Boundary | `tests/unit/test_phase1_authorization.py:1332` | **PARTIAL** | `verify_capability()` tests mismatch when parameter supplied, but `TrustedExecutionBoundary.execute_protected_action` never supplies it (`provenance.py:396`). End-to-end enforcement is missing. |
| **3. Cross-Task Capability Reuse** | **ENFORCED** (Task ID bound & validated) | `tests/unit/test_trusted_task_contract.py:85`, `tests/unit/test_execution_boundary_enforcement.py:280` | **PASS** | `task_id` is bound in capability, checked against active contract, and verified in `verify_capability()`. |
| **4. Target Substitution & Extraction** | **PARTIAL** (Digest verified; extraction heuristic) | `tests/unit/test_trusted_tool_registry.py:65, 185` | **PARTIAL** | Digest mismatch correctly blocks execution; however, positional argument target extraction (`tools.py:136`) is not adversarially tested. |
| **5. Object Ownership Violations** | **UNENFORCED** (No ownership concept) | None | **MISSING** | No tests exist for object-level ownership or principal-to-record authorization. |
| **6. Cross-Tenant Access** | **UNENFORCED** (No tenant boundaries) | None | **MISSING** | No multi-tenancy models or tests exist in the codebase. |
| **7. Unauthorized Protected-Field Mutation**| **UNENFORCED** (No field-level gating) | None | **MISSING** | `SENSITIVE_FIELDS` is only tested for egress/log masking (`test_models.py:210`). No field mutation restrictions exist. |
| **8. Unauthorized Collection Results** | **UNENFORCED** (No collection filtering) | None | **MISSING** | No tests evaluate per-item post-filtering of collection/list returns. |
| **9. Permission Revocation Detection** | **ENFORCED** for Tokens; **UNENFORCED** for Resources | `tests/unit/test_phase1_authorization.py:512`, `tests/unit/test_trusted_tool_registry.py:140` | **PASS** (Token) / **MISSING** (Resource) | Token revocation via `revoke_capability` is strictly enforced. Changes to underlying resource state/permissions are unmonitored. |
| **10. Alternate Invocation Paths** | **PARTIAL** (Option A executor binding) | `tests/unit/test_execution_boundary_enforcement.py:820`, `tests/unit/test_trusted_tool_registry.py:205` | **PARTIAL** | Option A object identity (`is`) prevents unverified callables from presenting tokens. Direct call of `_executor_func` is untested. |
| **11. Unauthenticated Observatory Access** | **UNENFORCED** (Public read-only GETs) | `tests/ui/test_server.py:35-120` | **PARTIAL** | Tests confirm endpoints return HTTP 200 without authentication; no access control tests exist. |

---

## 5. Prioritized Remediation Plan

Remediations are divided into distinct categories to preserve working mechanisms while systematically addressing demonstrated gaps.

### Category A: Confirmed Security Defects (Immediate Remediations)
1. **Pass and Verify Principal Identity at Consequential Execution Boundary:**
   - *Impact:* High. Closes SEC-01.
   - *Scope:* Minimal (< 15 lines).
   - *Action:* In `epistemicos/provenance.py`, add `principal_id: Optional[str] = None` to `ExecutionContext`. In `TrustedExecutionBoundary.execute_protected_action()`, retrieve `principal_id` from `context` and pass `principal_id=context.principal_id` to `self.authority.verify_capability()`. In `TrustedToolWrapper.__call__()`, populate `boundary_ctx.principal_id = cap.principal_id`.

2. **Harden Tool Target Extraction Precedence:**
   - *Impact:* High. Closes SEC-03.
   - *Scope:* Small (< 25 lines).
   - *Action:* In `epistemicos/tools.py`, disable fallback to `args[0]` when `target_param` is undefined on non-read-only actions. Require explicit declaration of target parameters or raise `ValueError` at tool registration time for state-mutating actions.

### Category B: Missing Security Invariants (Architectural Enhancements)
3. **Bind Authenticated Ingress Context:**
   - *Impact:* High. Addresses SEC-02.
   - *Scope:* Medium.
   - *Action:* Implement an `AuthenticatedSecurityContext` dataclass containing cryptographic signatures or trusted session tokens. Reject bare string dictionaries in `TrustedToolWrapper.__call__(context=...)`.

4. **Introduce Object-Level Ownership Evaluation in Policies:**
   - *Impact:* Medium-High. Addresses SEC-04.
   - *Scope:* Medium.
   - *Action:* Expand `Policy` to support an optional `ownership_resolver: Callable[[str, str, Dict[str, Any]], bool]` that verifies whether the principal owns or is authorized for the specific object ID within the resource path.

5. **Introduce Field Mutation Allow/Block Lists:**
   - *Impact:* Medium. Addresses SEC-05.
   - *Scope:* Medium.
   - *Action:* Allow `Policy` and `TrustedTaskContract` to declare `allowed_mutation_fields: Set[str]` and `prohibited_mutation_fields: Set[str]`. In `TrustedExecutionBoundary`, inspect top-level dictionary payload keys before executing the closure.

### Category C: Deployment and Configuration Risks
6. **Observatory Authentication & Token Redaction:**
   - *Impact:* Medium. Addresses SEC-06.
   - *Scope:* Small (< 30 lines).
   - *Action:* In `epistemicos/ui/server.py`, add optional API key verification via `Authorization: Bearer <key>`. In `epistemicos/ui/adapters.py`, redact `authorization_token_id` in `/api/traces` responses (e.g. `AUTH-CAP-***[REDACTED]***`). Refuse binding to non-loopback IPs unless `--auth-secret` is specified.

### Category D: Test Coverage Deficiencies
7. **Adversarial End-to-End Regression Harness:**
   - *Impact:* High.
   - *Scope:* Add dedicated tests for cross-principal capability presentation, ambiguous positional argument extraction, and unauthenticated Observatory exposure.

---

## 6. Regression Test Specifications

To establish a verified baseline, the following adversarial test specifications demonstrate the exact failure modes and will confirm subsequent remediations.

### Test Specification 1: Cross-Principal Capability Presentation (Demonstrating SEC-01)
```python
def test_cross_principal_capability_presentation_rejected():
    """
    Demonstrates SEC-01: A capability issued to Principal A must NOT be executable
    by an ExecutionContext claiming or representing Principal B.
    """
    authority = AuthorizationAuthority(
        default_policy=Policy(
            policy_id="test_p",
            allowed_operations={"write_record"},
            allowed_resources={"/records/1"},
            allowed_principals={"principal_alice", "principal_bob"}
        )
    )
    boundary = TrustedExecutionBoundary(authority=authority)

    def target_executor():
        return {"status": "executed"}

    # Issue capability specifically to Alice
    digest = boundary.compute_canonical_digest({"op": "write_record"})
    cap, reason = authority.evaluate_and_issue_capability(
        action_name="write_record",
        target="/records/1",
        canonical_request_digest=digest,
        principal_id="principal_alice",
        executor_id=target_executor
    )
    assert cap is not None

    # Construct context presented by Bob
    ctx_bob = ExecutionContext(
        correlation_id="corr-1",
        request_id="req-1",
        authorization_token_id=cap.token_id,
        authorized_digest=digest,
        authorization_granted=True,
        # EXPECTED DEFENSE: principal_id="principal_bob"
    )

    # In the current codebase, execute_protected_action succeeds because principal_id is ignored!
    # With remediation, this must raise PermissionError: CAPABILITY_VERIFICATION_FAILED_PRINCIPAL_MISMATCH
```

### Test Specification 2: Ambiguous Positional Argument Target Spoofing (Demonstrating SEC-03)
```python
def test_ambiguous_positional_target_extraction_rejected():
    """
    Demonstrates SEC-03: Positional non-resource arguments must not be accepted
    as the authorized target resource.
    """
    def log_and_mutate(audit_note: str, destination_table: str, data: dict):
        return "mutated"

    registry = TrustedToolRegistry()
    wrapper = registry.register_tool(
        tool_id="mutate_tool",
        action_name="mutate",
        executor_func=log_and_mutate,
        # Notice: target_param is NOT registered
        policy=Policy(
            policy_id="test_p",
            allowed_operations={"mutate"},
            allowed_resources={"audit_note_harmless"} # Restricts to this string
        )
    )

    # Attacker passes "audit_note_harmless" as first positional arg, but targets "critical_system"
    # Current behavior: wrapper extracts "audit_note_harmless", passes policy, and executes against "critical_system"
    # Expected defense: Tool extraction must reject ambiguous positional extraction for mutating tools.
```

### Test Specification 3: Unauthenticated Observatory Trace Reconnaissance (Demonstrating SEC-06)
```python
def test_observatory_api_requires_authentication():
    """
    Demonstrates SEC-06: Sensitive trace endpoints must not respond with full
    authorization token IDs and payload digests to unauthenticated requests.
    """
    # Query /api/traces on Observatory server without Authorization header
    # Current behavior: HTTP 200 OK with unredacted authorization_token_id and canonical_request_digest
    # Expected defense: HTTP 401 Unauthorized, or tokens masked as [REDACTED]
```

---

## 7. Audit Conclusion

EpistemicOS has constructed solid, mathematically rigorous foundations for tamper-evident provenance, replay prevention, and execution fencing. However, in its current state, **authorization decisions are not rigorously bound to authenticated principals, object-level ownership boundaries, or field-level mutations**.

By applying the targeted, surgical remediations detailed in Section 5—specifically threading `principal_id` through `ExecutionContext` into `TrustedExecutionBoundary.execute_protected_action()`, eliminating heuristic positional target fallbacks, and introducing object-ownership predicates—EpistemicOS can close the CVE-2026-118539 threat vectors with minimal code modification while fully preserving its low-latency, deterministic execution guarantees.
