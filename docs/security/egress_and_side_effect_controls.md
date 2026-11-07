# Phase 2 — Default-Deny Network Egress and Externally Consequential Action Controls

This document specifies the EpistemicOS Phase 2 control-plane security architecture, network egress policy enforcement, action classification taxonomy, typed human approval contracts, and deployment boundaries.

---

## 1. Overview & Motivating Incident Threat Model

Phase 2 builds upon Phase 1's trusted authorization authority, action-bound capabilities, and controlled execution boundary.

The motivating incident scenarios include:
- **Egress Pivot Attacks**: Agents pivoting from failed in-scope cybersecurity tasks to unrelated public GitHub repositories or external servers.
- **Identity Synthesis & Fake Personas**: Creating unauthorized accounts on external services or platforms.
- **Unauthorized Artifact Publication**: Publishing, opening, or modifying public pull requests, issues, releases, packages, or executable code.
- **Unsanctioned Human Contact**: Contacting repository maintainers or sending emails/messages without explicit typed human approval.
- **Prompt Continuation Exploitation**: Treating generic, automated continuation messages ("continue", "proceed", "best judgement") as authorization grants.

---

## 2. Egress Policy Architecture & Destination Normalization

### 2.1 Default-Deny Network Policy (`EgressPolicy`)
In protected mode, external network access is **default-deny**:
- An absent or empty approved-egress policy strictly denies external network access.
- A destination hostname being public or DNS-resolvable does not imply authorization.
- Policy configuration requires explicit registration of allowed hostnames, fully-qualified wildcards (e.g. `*.api.github.com`), allowed protocols (`http`, `https`), allowed ports (`80`, `443`), and allowed action categories.

### 2.2 Destination Normalization (`normalize_destination_host`)
To eliminate SSRF and parsing ambiguity bypasses:
- **Userinfo & Delimiter Sanitization**: Rejects URLs containing userinfo with `#` or `%23` fragments in the authority component.
- **IPv6 Representation**: Strips brackets and normalizes IPv6 representations (including IPv4-mapped IPv6 addresses).
- **Alternate Numeric IP Encodings**: Normalizes decimal integer (`2130706433`), hexadecimal (`0x7f000001`), octal (`0177.0.0.1`), and dotted octal IP encodings to canonical IPv4 strings before policy matching.
- **Trailing Dot Removal**: Strips DNS FQDN trailing dots (`example.com.`).
- **Scheme-Rest Lowercasing**: Normalizes scheme-rest and hostnames to lowercase.

---

## 3. Transport-Boundary Egress Enforcement (`EgressTransportBroker`)

### 3.1 Point-of-Establishment Verification & Transport Boundary
URL argument inspection alone is insufficient against socket-level requests, redirects, or raw callbacks.
The `EgressTransportBroker` and `ControlledEgressTransport`:
1. Intercept connection establishment at the transport boundary before network socket creation.
2. Resolve DNS strictly via registered/approved resolvers.
3. Re-validate **all** returned DNS IP addresses against restricted IP ranges (loopback `127.0.0.1`/`::1`, private `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, link-local `169.254.0.0/16`, AWS/GCP metadata endpoints `169.254.169.254` and `metadata.google.internal`). If any returned answer is restricted, the connection is denied.
4. Pin the validated IP address to prevent DNS rebinding (TOCTOU) attacks between authorization and connection time.
5. Re-validate every HTTP redirect target URL strictly before the redirected request is made across arbitrary redirect chains.
6. Intercept direct `socket.connect` calls in protected execution scope via `enforce_socket_boundary()`.

### 3.2 Audit & Provenance Recording
Failed egress attempts record an explicit `EGRESS_BLOCKED` provenance event into `LocalProvenanceStore` bound to the correlation ID, request ID, target URL, normalized host, resolved IP, and denial reason without leaking sensitive credentials or payload data.

---

## 4. Action Classification Taxonomy & Typed Human Approval Controls

### 4.1 Trusted Action Categories (`ActionCategory` & `ActionRegistry`)
Operations are classified by their real-world consequences, ignoring model self-descriptions or automated natural language claims:
1. `READ_ONLY_LOCAL`: Read-only operations on local/test resources.
2. `NETWORK_READ`: Network reads against explicitly approved hosts.
3. `EXTERNAL_RECONNAISSANCE`: Reconnaissance against newly discovered external targets.
4. `ACCOUNT_CREATION`: Account creation or identity changes on external services.
5. `MESSAGING_CONTACT`: Sending email, messaging, or contacting humans.
6. `PUBLIC_REPOSITORY_MUTATION`: Modifying public repositories, issues, PRs, or releases.
7. `PACKAGE_PUBLISHING`: Publishing packages, artifacts, or executables.
8. `CREDENTIAL_USAGE`: Using discovered credentials or cross-agent resources.
9. `DESTRUCTIVE_COMMAND`: Destructive shell or filesystem operations.
10. `STATE_MUTATION`: Persistent financial or account state-changing operations.

### 4.2 Typed Human Approval Requirements (`HumanApprovalRecord` & `TypedHumanApprovalRecord`)
Externally consequential side effects and approval-required operations require explicit typed human approval with independent principal authority verification:
- **Binding Contract**: Approvals strictly bind `approval_id`, `approver_id`, `action_name`, `target`, `action_digest`, `request_id`, `policy_version`, `requesting_principal`, `approver_assertion`, `task_id`, and HMAC-SHA256 signature.
- **Generic Responses Rejected**: Generic prompts ("continue", "proceed", "best judgement") or automated LLM worker messages cannot authorize side effects.
- **Cryptographic Approval Record Integrity vs. Principal Authority**:
  - *Cryptographic Signature Validity*: A valid HMAC signature demonstrates possession of the signing secret and payload tamper resistance. It does *not* prove that `approver_id` represents an authenticated human with genuine authority.
  - *Independent Principal Authentication*: The approving principal's identity must be independently proven through `PrincipalVerifier` via an asymmetric cryptographic assertion (`AuthenticatedPrincipal`) issued by a trusted identity authority (e.g. Ed25519-signed identity token).
  - *Approver Authorization under Applicable Policy*: Even if authenticated, the verified approver principal must be explicitly permitted under `policy.allowed_approvers`.
  - *Exact Context and Scope Binding*: The approval must strictly bind to the exact requesting principal (`effective_principal`), task ID, action, canonical target, request ID, and canonical request digest. Self-approval (`approver == requesting_principal`) is unconditionally rejected.
  - *Downstream Capability Verification*: The issued `Capability` carries verified approver identity and provenance. `AuthorizationAuthority.verify_capability()` independently re-validates the carried approver provenance against `PrincipalVerifier` and verifies exact field consistency prior to execution.
- **Fundamental Threat Limitation (Social Engineering & Coercion)**:
  - *Middleware Verification Boundary*: EpistemicOS authorization middleware can mathematically and cryptographically verify the authenticity and integrity of identity and approval assertions supplied by trusted identity providers.
  - *Threat Model Limitation*: Cryptographic and provenance checks *cannot* independently verify whether an authorized human was deceived by social engineering, phishing, coercion, or pretexting. Identity verification guarantees *who* approved the operation, not that the approver exercised flawless human judgment.
- **Capability Invalidation**: Target, action, digest, requester, or task substitutions after grant issuance immediately invalidate capability verification.

### 4.3 Route Change & Alternate Route Violation Tracking
Exhausting in-scope routes does not expand the egress allowlist. Every alternate route or discovered target requires its own authorization check.
Repeated scope violations increment a supervisory counter (`SideEffectPolicyEngine.get_violation_count`) for audit alerting.

### 4.4 Restriction Inheritance across Alternative Execution Paths
When a consequential or protected operation is denied for a specific task, EpistemicOS enforces **Persistent Denial and Restriction Inheritance**:
- **Invariant**: An execution restriction or denial governing a task or target resource cannot be bypassed merely by switching tools, endpoints (e.g. trailing slash `/api/v1/user/delete/` vs `/api/v1/user/delete` or subpaths), or execution methods (`delete_db` vs `destructive_shell`).
- **Enforcement Mechanics**:
  1. `CapabilityRegistry._check_denial_unlocked` checks active task denials recorded in durable append-only persistence (`logs/denial_registry.jsonl`).
  2. Target matching normalizes resource strings (stripping trailing slashes and checking subpath overlaps).
  3. Action classification via `ActionRegistry.classify_action` matches action categories to prevent category evasion (e.g., retrying a denied database deletion via raw shell commands).
  4. Non-consequential local read operations (`READ_ONLY_LOCAL`, `NETWORK_READ`) are not blocked by restrictions on unrelated targets.
- **Reauthorization**:
  - **Operation-Specific Reauthorization**: Clears a denial for a specific operation payload by providing an expected canonical request digest (`expected_action_digest`). When `expected_action_digest` is supplied to `clear_denial_with_approval()`, clearance fails closed if the `HumanApprovalRecord.action_digest` is missing, empty, or mismatched.
  - **Task-Level Administrative Clearance**: When `expected_action_digest` is omitted, the approval record acts as a task-level administrative clearance bound strictly to `task_id`, `action_name`, `target`, and HMAC signature with explicit `CLEAR_DENIAL` intent.

---

## 5. ShowerCurtain Outbound Inference Egress Path

The `ShowerCurtainOpenAIAdapter` wraps model inference requests:
1. Executes Stage A-E privacy transformations and sensitive data redaction.
2. Passes transformed payload through `ShowerCurtainGate`.
3. Verifies provider target URL (`api.openai.com`, `api.anthropic.com`) against `EgressTransportBroker` before external transmission.
4. Preserves fail-closed privacy rules (credential and PII protection) on the outbound path.

---

## 6. Context-Aware Data Transfer Governance (SRG / Luna Moth Threat Model)

### 6.1 Threat Model & Governing Principle
The motivating threat model is **Silent Ransom Group (SRG / Luna Moth)**, known for utilizing legitimate administration tools (e.g., Rclone, WinSCP) and approved, reputable cloud storage services (e.g., Microsoft OneDrive, Google Drive) as unauthorized exfiltration conduits.

The governing principle of EpistemicOS data transfer governance is:
> **A legitimate executable or approved destination hostname does not make a particular data transfer legitimate.**

Egress governance cannot rely solely on destination allowlisting or malware signatures. A hostname allowlist granting access to `graph.microsoft.com` or `www.googleapis.com` must not permit an agent or tool to exfiltrate confidential records to an employee's personal account or an attacker-controlled workspace.

### 6.2 The Typed Transfer Context (`DataTransferContext`)
Data movement decisions are evaluated against a typed, validated contract:
1. **Initiating Principal**: The authenticated identity initiating the transfer.
2. **Destination Identity (`DestinationIdentity`)**: The fine-grained destination target—including the provider service (`onedrive`, `google_drive`, `s3`), specific approved `tenant_id`, `account_id`, or `workspace_id`, alongside the normalized host and endpoint.
3. **Data Classification (`DataClassification`)**: Ordered sensitivity (`PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED`). Classification must originate from trusted policy or verified metadata, not arbitrary agent assertions (`is_classification_trusted=True`).
4. **Operation & Direction**: Specific transfer verbs (`READ`, `WRITE`, `SYNC`, `BACKUP`, `EXPORT`) and directions (`UPLOAD`, `DOWNLOAD`, `SYNCHRONIZE`, `REPLICATE`).
5. **Transfer Volume**: Both declared byte count and actual observed/transmitted bytes, bounded by per-transfer limits and cumulative task/request budgets.
6. **Explicit Authorization**: Verification that capability tokens bind exactly to the authorized destination tenant and scope, preventing cross-destination capability reuse.

### 6.3 In-Process vs. Deployment Enforcement Boundaries
- **In-Process Python Boundary**:
  - `ControlledEgressTransport` and `EgressTransportBroker` enforce pre-flight and in-flight payload byte inspection, destination tenant validation, and capability binding for managed Python HTTP/HTTPS connections.
  - Declared sizes are validated against actual observed payload lengths; transfers are aborted before or during transmission if limits are breached.
- **Deployment-Level Boundary (Residual Gap)**:
  - Application-level Python middleware cannot inspect or terminate unmanaged native binaries, subprocesses (e.g. standalone CLI `rclone` or `winscp` invocations outside Python tool wrappers), or raw C-extensions bypassing Python socket boundaries.
  - OS-level network isolation (iptables/nftables, network namespaces `netns`, or mandatory egress proxying with TLS interception and tenant-header enforcement) remains mandatory in untrusted execution environments.
- **Provider Identity Limitations**:
  - When cloud providers do not expose verifiable tenant or account identifiers within unauthenticated network connection requests (e.g., standard generic HTTPS calls prior to OAuth token exchange), policy must require either an authenticated capability asserting the destination tenant or fail closed.

---

## 7. Deployment Boundary & Infrastructure Requirements

### 7.1 Application-Level Checks vs. Deployment Infrastructure (GAP-03 Status: PARTIAL)
- **Enforced Outbound Paths**: Application-level Python HTTP requests (`ControlledEgressTransport`, `ShowerCurtainOpenAIAdapter`), `EgressTransportBroker` connections, `ContainmentGuard.inspect_network_egress()` / `wrap_tool_execution()`, and direct `socket.connect` calls within `enforce_socket_boundary()` protected execution scope.
- **Deployment Infrastructure Requirements**: OS-level network isolation, egress firewall rules (iptables/nftables), enforced HTTP egress proxy, or network namespaces (`netns`). Application-level Python code cannot replace OS-level process isolation.

### 7.2 Deployment Enforcement Invariants
When deployed in protected mode with `require_infrastructure_enforcement=True`, `EgressTransportBroker` verifies the presence of infrastructure-level network enforcement (`infrastructure_enforced=True`) and fails startup if missing.

### 7.3 Remaining Library-Level Bypass Routes & Status Verdict
The overall GAP-03 status remains `PARTIAL` (and `PARTIAL_GATING_DEFENSE` in Incident Lab evidence reports) because:
- Direct Python socket calls and HTTP transports are authoritatively enforced at the transport boundary within the process.
- Subprocesses (`curl`/`wget`/raw shell execution) and raw C-extensions bypassing Python's `socket` module require container/OS-level network isolation (iptables or netns).
- Egress policy enforcement is fail-closed, DNS-rebind-protected, and provenance-audited.
