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

### 4.2 Typed Human Approval Requirements (`TypedHumanApprovalRecord`)
Externally consequential side effects require explicit typed human approval:
- **Binding Contract**: Approvals strictly bind `approval_id`, `operation_id`, `target_resource`, `canonical_args_digest`, `task_id`, `policy_version`, `approved_by_principal`, `timestamp`, and HMAC-SHA256 signature.
- **Generic Responses Rejected**: Generic prompts ("continue", "proceed", "best judgement") or automated LLM worker messages cannot authorize side effects.
- **Capability Invalidation**: Target or operation changes after grant issuance immediately invalidate the capability token.

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
- **Reauthorization**: Active persistent denials can be cleared if and only if an authorized principal provides a cryptographically authenticated `HumanApprovalRecord` with explicit clearance intent (`CLEAR_DENIAL`), bound to the specific `task_id`, `action_name`, `target`, and `action_digest`.

---

## 5. ShowerCurtain Outbound Inference Egress Path

The `ShowerCurtainOpenAIAdapter` wraps model inference requests:
1. Executes Stage A-E privacy transformations and sensitive data redaction.
2. Passes transformed payload through `ShowerCurtainGate`.
3. Verifies provider target URL (`api.openai.com`, `api.anthropic.com`) against `EgressTransportBroker` before external transmission.
4. Preserves fail-closed privacy rules (credential and PII protection) on the outbound path.

---

## 6. Deployment Boundary & Infrastructure Requirements

### 6.1 Application-Level Checks vs. Deployment Infrastructure (GAP-03 Status: PARTIAL)
- **Enforced Outbound Paths**: Application-level Python HTTP requests (`ControlledEgressTransport`, `ShowerCurtainOpenAIAdapter`), `EgressTransportBroker` connections, `ContainmentGuard.inspect_network_egress()` / `wrap_tool_execution()`, and direct `socket.connect` calls within `enforce_socket_boundary()` protected execution scope.
- **Deployment Infrastructure Requirements**: OS-level network isolation, egress firewall rules (iptables/nftables), enforced HTTP egress proxy, or network namespaces (`netns`). Application-level Python code cannot replace OS-level process isolation.

### 6.2 Deployment Enforcement Invariants
When deployed in protected mode with `require_infrastructure_enforcement=True`, `EgressTransportBroker` verifies the presence of infrastructure-level network enforcement (`infrastructure_enforced=True`) and fails startup if missing.

### 6.3 Remaining Library-Level Bypass Routes & Status Verdict
The overall GAP-03 status remains `PARTIAL` (and `PARTIAL_GATING_DEFENSE` in Incident Lab evidence reports) because:
- Direct Python socket calls and HTTP transports are authoritatively enforced at the transport boundary within the process.
- Subprocesses (`curl`/`wget`/raw shell execution) and raw C-extensions bypassing Python's `socket` module require container/OS-level network isolation (iptables or netns).
- Egress policy enforcement is fail-closed, DNS-rebind-protected, and provenance-audited.
