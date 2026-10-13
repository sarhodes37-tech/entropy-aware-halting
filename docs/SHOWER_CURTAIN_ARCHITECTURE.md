# Shower Curtain: Local-First Privacy Mediation Subsystem in EpistemicOS

## Architecture Assessment & System Design Document

### 1. Executive Overview & Mission

The **Shower Curtain** subsystem is a modular, local-first privacy mediation layer for EpistemicOS. It forms a secure trust boundary between local users/clients and external, potentially untrusted AI inference providers (such as OpenAI, Anthropic, or custom remote LLMs).

The governing principle of Shower Curtain is:
> *«Give the remote model the minimum information necessary to perform the authorized task, retain control of sensitive context locally, and make every disclosure decision inspectable and enforceable.»*

### 2. EpistemicOS Architecture Integration

Shower Curtain seamlessly integrates into the EpistemicOS control plane without modifying existing core logic or introducing external runtime dependencies:
- **Governance Gate Integration**: Implements `ShowerCurtainGate` adhering to the standard EpistemicOS `Gate` interface (`evaluate(payload, context) -> GateResult`).
- **Audit Logging**: Uses `TamperEvidentAuditTrail` (`AuditEvent`, `AuditLogLevel`) to record cryptographic hashes and sanitized metadata without logging raw PII/credentials.
- **Receipt Generation**: Integrates with `ReceiptGenerator` to mint verifiable, signed privacy receipts detailing detections, transformations, policy decisions, and egress gate outcomes.
- **Zero External Dependencies**: Implemented strictly using standard library Python (`re`, `hashlib`, `hmac`, `json`, `math`, `ipaddress`, `dataclasses`, `enum`, `typing`, `secrets`).

### 3. Trust Boundaries & Data Flow Diagram

```
+-----------------------------------------------------------------------+
|                         LOCAL TRUST BOUNDARY                          |
|                                                                       |
|  [ User / Client ]                                                    |
|         │                                                             |
|         ▼                                                             |
|  [ Shower Curtain Privacy Engine ]                                    |
|    ├── Stage A: Deterministic Detector (PII, Credentials, Patterns)  |
|    ├── Stage B: Policy Evaluation Engine (PASS, REDACT, PSEUDO, etc.) |
|    ├── Stage C: Local Mapping Vault (Session Scope, Reversible Pseudonyms)|
|    ├── Stage D: Context Minimization Broker (Selective Disclosure)    |
|    ├── Marginal Privacy Utility (MPU) Evaluator (ΔU / ΔL Heuristic)   |
|    └── Stage E: Egress Policy Gate (Fail-Closed Enforcement)          |
|         │                                                             |
+---------┼-------------------------------------------------------------+
          │  Sanitized Outbound Payload (TLS)
          ▼
+-----------------------------------------------------------------------+
|                    UNTRUSTED REMOTE MODEL PROVIDER                     |
|  [ External Inference API (OpenAI / Anthropic / Remote Host) ]        |
+---------┼-------------------------------------------------------------+
          │  Remote Response / Tool Call Arguments
          ▼
+-----------------------------------------------------------------------+
|                         LOCAL TRUST BOUNDARY                          |
|                                                                       |
|  [ Inbound Response Inspector ]                                        |
|    ├── Leakage / Disclosed Local Values Detection                     |
|    ├── Controlled Rehydration (Authorized Pseudonyms ONLY)            |
|    └── Secret Restoration Suppression (Credentials NEVER restored)    |
|         │                                                             |
|         ▼                                                             |
|  [ Audit Log & Receipt Generator ]                                    |
|         │                                                             |
|         ▼                                                             |
|  [ User / Local Client ]                                              |
+-----------------------------------------------------------------------+
```

---

### 4. Pipeline Stages & Detailed Requirements

#### Stage A: Sensitive Information Detection
- **Deterministic Baseline**: Regex patterns, checksum validators (Luhn for Credit Cards), entropy analysis (for API keys/tokens), and configurable dictionaries.
- **Supported Categories**:
  - Direct PII (Names, Emails, Phone numbers, Physical Addresses)
  - Government Identifiers (SSN, Passport numbers, Tax IDs)
  - Financial Account Information (Credit Card numbers, IBAN, Bank routing/account numbers)
  - Authentication Credentials (API keys, Tokens, Private keys, Bearer tokens, passwords)
  - Configurable Entities (Employers, Project names, Custom terms)
  - Structural Identifiers (Absolute file paths, IP subnets)
- **Typed Metadata**: Returns `DetectionResult` objects with category, matched text, span `(start, end)`, confidence, and suggested treatment.

#### Stage B: Classification & Policy Evaluation
- **Explicit Policy Rules**: Policy model mapping data categories and sensitivity levels to distinct treatments:
  1. `PASS`: Permit explicit disclosure.
  2. `REDACT`: Irreversible placeholder (`[REDACTED_EMAIL]`).
  3. `PSEUDONYMIZE`: Stable, session-scoped reversible placeholder (`PERSON_1`, `PROJECT_A`).
  4. `GENERALIZE`: Reduce precision (`2020s` instead of `2026-03-31`, `US-CA` instead of exact zip code).
  5. `TRANSFORM`: Apply approved semantic transformation.
  6. `BLOCK`: Prevent outbound request if policy cannot be satisfied.
- **Conservative Defaults**: Secrets and API keys are strictly `REDACT` or `BLOCK` by default.

#### Stage C: Consistent Pseudonymization & Local Mapping Vault
- **Session-Scoped Isolation**: Mapping tables are bound to explicit `session_id`s. Zero leakage across session boundaries.
- **Reversible Mapping**: Maps `raw_value <-> placeholder` within session scope.
- **Protections**:
  - Secrets/credentials are **never** stored in the vault.
  - Vault key management: Derived via HMAC-SHA256 from local master key and session ID.
  - Rehydration restriction: Only registered session placeholders can be rehydrated inbound. Unknown or fabricated placeholders (e.g. injected by LLM) are left untransformed.

#### Stage D: Context Minimization Broker
- Selectively supplies context necessary for the task.
- Evaluates total history and retrieved context against sensitivity and relevance scores.
- Trims unnecessary background history before transmission.

#### Marginal Privacy Utility (MPU) Evaluator
- Evaluates candidate disclosures using the decision heuristic:
  $$\text{MPU} = \frac{\Delta U}{\Delta L + \epsilon}$$
  - $\Delta U$: Estimated improvement in task utility.
  - $\Delta L$: Estimated incremental privacy leakage based on sensitivity weight and disclosure volume.
  - Prevents division by zero using $\epsilon = 10^{-6}$.
  - Allows configurable MPU thresholds to automatically block low-utility, high-leakage disclosures.

#### Stage E: Egress Gate
- Inspects the **final serialized payload** (messages, tool definitions, tool arguments, attachments).
- Enforces fail-closed behavior on policy-critical uncertainty.
- Returns structured denials without reproducing sensitive inputs.

---

### 5. Integration Interfaces & Dry-Run Mode

- **Core Engine Interface**: `ShowerCurtainEngine.transform_request()` and `process_response()`.
- **Dry-Run Mode**: Enables inspection of proposed transformations and detected items without making external calls or modifying state.
- **Provider Adapter**: `ShowerCurtainOpenAIAdapter` wraps model calls (like OpenAI completions or generic HTTP payloads) with inbound/outbound transformations.

---

### 6. Architectural Decision Records (ADR)

1. **ADR-001: Standard Library Zero Dependency Implementation**
   - *Decision*: Build Shower Curtain entirely with Python stdlib.
   - *Rationale*: Preserves EpistemicOS core performance guarantees (O(1) low-latency evaluation) and zero dependency bloat.

2. **ADR-002: Rehydration Safety & Fabricated Placeholder Rejection**
   - *Decision*: Inbound rehydration requires exact match in the local vault for the specific session.
   - *Rationale*: Prevents remote models or prompt injection payloads from inventing placeholders (`PERSON_999`) to exfiltrate arbitrary vault entries.

3. **ADR-003: Credentials Non-Restoration Invariant**
   - *Decision*: Redacted credentials (API keys, passwords) are permanently redacted and can never be rehydrated inbound.
   - *Rationale*: Complete mitigation of credential exfiltration vectors.
