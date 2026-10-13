# EpistemicOS Execution Provenance Subsystem

## Overview
The Execution Provenance subsystem provides an authoritative, independent execution record for agent-proposed actions, control-plane authorization decisions, and trusted executor operations. It explicitly decouples unauthenticated agent text claims from verified execution attestations.

## Provenance Event Model & Lifecycle
The complete lifecycle of a protected operation follows six distinct phases:

1. **Agent Action Proposal (`ACTION_PROPOSED`)**: Captured at the agent/tool adapter boundary (`AGENT_ADAPTER`).
2. **Control-Plane Evaluation (`AUTHORIZATION_GRANTED` / `AUTHORIZATION_DENIED`)**: Emitted directly by trusted governance gates (`GOVERNANCE_GATE`).
3. **Execution Invocation (`EXECUTION_STARTED`)**: Triggered at the trusted execution boundary (`EXECUTOR`) upon atomic token validation.
4. **Execution Completion (`EXECUTION_SUCCEEDED` / `EXECUTION_FAILED`)**: Emitted directly by the executor based on actual operation outcome.
5. **Egress Boundary Check (`EGRESS_BLOCKED`)**: Emitted by Shower Curtain (`EGRESS_GATE`) if egress policy violates outbound privacy constraints.
6. **Reconciliation (`RECONCILIATION_MISMATCH`)**: Computed by `ProvenanceReconciler` (`RECONCILER`) to compare proposed vs authorized vs executed records.

```
+----------------+      +------------------+      +-------------------+
| Agent Adapter  | ---> | Governance Gate  | ---> | Execution Boundary|
| ACTION_PROPOSED|      | AUTHORIZATION_*  |      | EXECUTION_*       |
+----------------+      +------------------+      +-------------------+
        |                         |                         |
        +-------------------------+-------------------------+
                                  |
                                  v
                      +----------------------+
                      | Provenance Reconciler|
                      +----------------------+
```

## Component Trust Boundaries & Assumptions
- **`AGENT_ADAPTER`**: Untrusted. Represents the agent proposing actions. Agent claims of success are treated as assertions, not evidence.
- **`GOVERNANCE_GATE`**: Trusted. Emits authorization decisions bound to canonical request digests and single-use authorization tokens.
- **`EXECUTOR`**: Trusted. Emits execution start and actual execution success/failure outcomes directly from code execution boundaries.
- **`EGRESS_GATE`**: Trusted. Evaluates outbound payloads and halts unauthorized data egress.
- **`RECONCILER`**: Trusted. Compares structured records across sources and reports policy violations.

## Threat Model & Local Adapter Limitations
- **Host-Level Compromise**: The `LocalProvenanceStore` utilizes append-only hash chaining and file locking (`fcntl.flock`). However, a local process or log file does not constitute an independent trust boundary against an attacker who has root access or host-level compromise.
- **Forgery Prevention**: Agents cannot emit `EXECUTION_SUCCEEDED` events because `ProvenanceSource.EXECUTOR` events are generated solely by `TrustedExecutionBoundary`.
- **Replay & Atomicity**: Single-use authorization tokens are consumed atomically using in-memory locks (`threading.Lock`) before execution proceeds.

## Failure & Availability Policy
- **Fail-Closed Strategy**: Default configuration enforces `fail_closed=True`. If the provenance store is unavailable or corrupted, execution of protected operations is halted immediately to prevent unrecorded actions.

## External Anchoring Integration
For enterprise deployments requiring protection against host-level compromise, `ProvenanceStore` defines an interface that can be backed by remote DLTs, SGX enclaves, or separately privileged remote audit microservices.
