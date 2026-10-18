# EpistemicOS Incident-Derived Security Test Lab — Architecture & Design Gate

## 1. Executive Summary

This document establishes the architecture, testability map, and design gate analysis for the **EpistemicOS Incident-Derived End-to-End Security Test Lab**.

The purpose of the lab is to provide an isolated, 100% reproducible, side-effect-observable security evaluation capability. The lab tests EpistemicOS against seven documented incident patterns involving credential exposure, authorization bypass, indirect egress, internal service access, unauthorized cryptocurrency-wallet operations, destructive recovery behavior, and multi-agent fleet amplification.

Unlike standard benchmark suites that measure raw accuracy or pass rates, this test lab independently measures:
1. **Dimension A — Security Outcome:** Whether unauthorized attempts are prevented, detected, or contained, with explicit accounting for execution boundary enforcement, observable side effects, and provenance integrity.
2. **Dimension B — Legitimate Task Behavior:** Whether legitimate, authorized operations succeed without false denials or unnecessary halting.

---

## 2. EpistemicOS Core Architecture & Testability Map

The EpistemicOS defense-in-depth architecture consists of six primary control-plane subsystems:

```
                                +----------------------------------+
                                |    Raw Request / Submission      |
                                +----------------------------------+
                                                 |
                                                 v
                                +----------------------------------+
                                | Canonical Problem Representation |
                                |      (Schema Validation)         |
                                +----------------------------------+
                                                 |
                                                 v
                                +----------------------------------+
                                |     Governance Gate Pipeline     |
                                |  - ShowerCurtainGate (Egress)    |
                                |  - PermissionGate (JIT Scope)    |
                                |  - EntropyGate (Surprisal)       |
                                |  - TriangulationGate (Integrity) |
                                +----------------------------------+
                                                 |
                                       +---------+---------+
                                       |                   |
                                   [HALTED]            [PASSED]
                                       |                   |
                                       v                   v
                    +--------------------+   +---------------------------+
                    | Vector Manager     |   | Trusted Execution         |
                    | Revokes Vectors    |   | Boundary                  |
                    +--------------------+   | - Provenance Store Lookup |
                                             | - Replay Prevention       |
                                             | - Executor Invocation     |
                                             +---------------------------+
```

### Subsystem Capabilities & Execution Mechanics

1. **`EpistemicOrchestrator` (`epistemicos/core.py`)**
   - Entry point: `process_submission(raw_payload, context, trajectory_id)`.
   - Validates schema against `CanonicalProblemRepresentation`.
   - Sequential evaluation of registered governance gates (`_evaluate_gates`).
   - If any gate halts: revokes trajectory vectors via `VectorHygieneManager`, logs audit event to `TamperEvidentAuditTrail`, and halts pipeline.
   - If all gates pass and an `actual_executable` callback is provided: dispatches execution through `TrustedExecutionBoundary.execute_protected_action`.

2. **`PermissionGate` (`epistemicos/gates.py`)**
   - Enforces scope constraints (`allowed_operations`, `allowed_resources`) on `proposed_actions`.
   - Requires explicit, non-ambiguous action contract details (`op` and `node`/`endpoint`/`resource`).
   - Resolves authorized scope strictly from server-controlled configuration (`self.trusted_scope` or `context.get("trusted_scope")`), ignoring request- or payload-supplied scope fields.
   - Performs deep regex inspection (`_deep_regex_inspection`) to intercept OS commands (`rm -rf`, `sudo`, `bash`, `curl`, `wget`), jailbreaks, and system overrides.

3. **`ShowerCurtainGate` & `ShowerCurtainEngine` (`epistemicos/shower_curtain/`)**
   - Inspects JSON payloads for sensitive PII, API tokens, passwords, and custom entities.
   - Replaces sensitive entities with mapping placeholders (Stage A–C) or enforces `BLOCK`/`REDACT` policy decisions (Stage E).
   - Side-effect-free in dry-run mode (`dry_run=True`).

4. **`TrustedExecutionBoundary` & `LocalProvenanceStore` (`epistemicos/provenance.py`)**
   - Atomically validates single-use authorization tokens (`authorization_token_id`) and canonical payload digests (`authorized_digest`).
   - Verifies store-backed `AUTHORIZATION_GRANTED` provenance events before calling `executor_func`.
   - Prevents replay attacks by recording consumed tokens and attempt IDs in memory and append-only hash-chained logs.

5. **`ContainmentGuard` (`epistemicos/containment.py`)**
   - Provides active ingress prompt filtering, URL/IP SSRF protection (`inspect_network_egress`), shell directive checking (`inspect_tool_command`), and goal mutation/reward-cheating detection (`inspect_goal_integrity`).
   - Operates as a standalone guard or tool execution wrapper (`wrap_tool_execution`).

6. **`VectorHygieneManager` (`epistemicos/vector_hygiene.py`)**
   - Manages trajectory vector lifetimes and revokes vectors automatically when a pipeline halts.

---

## 3. Evaluation of Existing Seven-Scenario Harness

An inspection of `benchmarks/run_e2e_security_evaluation.py` and `tests/e2e_security/` revealed several reusable strengths as well as key unsupported claims and component-level limitations:

### Reusable Artifacts
- **Side-effect tracking fixtures (`tests/e2e_security/scenario_fixtures.py`):** `SecretDisclosureCounter`, `ResourceAccessCounter`, `EgressTracker`, `InternalServiceTracker`, `MockWalletSimulator`, `GraderEnvironment`, and `FleetStateTracker` provide thread-safe, resettable counters.
- **Orchestrator integration:** Submitting raw payloads through `EpistemicOrchestrator.process_submission` properly exercises `PermissionGate` and `ShowerCurtainGate`.

### Identified Component-Level Evidence & Unsupported Claims
1. **Unexecuted Callbacks in Legitimate Control Tests:** In the prior evaluation harness, legitimate control cases (e.g. `S1-BENIGN`, `S2-BENIGN`) passed `process_submission` with `status: "ALLOWED"`, but did NOT provide an `actual_executable` callback in `context`. As a result, `TrustedExecutionBoundary.execute_protected_action` was skipped, and callback execution was marked `UNTESTED_NO_MANUAL_GRANT`.
2. **Component-Level Fleet Tracking (Case 7):** In Scenario 7, `FleetStateTracker` tracked aggregate attempts and credential reuse outside `EpistemicOrchestrator`. `EpistemicOrchestrator` itself lacked a fleet governance gate in its default pipeline.
3. **Implicit Egress Guard Integration (Case 3):** `ContainmentGuard.inspect_network_egress` was not registered as a default gate in `EpistemicOrchestrator`. `ShowerCurtainGate` caught sensitive PII tokens in URLs, but non-PII GET query parameters required explicit `ContainmentGuard` inspection or scope gating.

---

## 4. Documented Architectural Gaps & Integration Limitations

In accordance with Section 1 of the specification, architectural gaps in EpistemicOS are explicitly documented below rather than covered by production workarounds:

| Gap / Limitation ID | Architectural Gap Description | Impact on Security Testing | Testability Status Label |
|---|---|---|---|
| **GAP-01: Multi-Agent Fleet Gate** | `EpistemicOrchestrator` manages per-trajectory state but lacks a built-in cross-agent fleet tracker gate in its default pipeline. | Fleet aggregate budget and cross-agent credential reuse must be evaluated at the component level via `FleetStateTracker` or a dedicated fleet wrapper. | `COMPONENT_LEVEL_FLEET_EVIDENCE` |
| **GAP-02: Automatic Grant Provenance** | Governance gates inside `process_submission` validate permission scope but do not automatically issue store-backed `AUTHORIZATION_GRANTED` provenance events into `LocalProvenanceStore`. | Submitting an `actual_executable` callback without prior store grant causes `TrustedExecutionBoundary` to halt execution. Positive control tests that do not seed manual grants must report callback execution as untested. | `UNTESTED_NO_MANUAL_GRANT` |
| **GAP-03: ContainmentGuard Gate Registration** | `ContainmentGuard` is an independent module and is not registered in `EpistemicOrchestrator.gates` by default. | Network URL SSRF and tool command parameters passed in unstructured payloads are evaluated via `ContainmentGuard.wrap_tool_execution` or `PermissionGate` regex, rather than a built-in orchestrator gate. | `COMPONENT_LEVEL_EGRESS_GUARD` |
| **GAP-04: Crypto-Wallet Signing Gate** | EpistemicOS lacks a dedicated cryptocurrency transaction signing gate in `EpistemicOrchestrator` (only general scope checks in `PermissionGate` and ML-DSA algorithm checks in `CryptoAttestationGate`). | Wallet operations are gated via `PermissionGate` scope checks (`allowed_operations`). Local wallet simulator signing/deployment is checked at the execution boundary. | `PASSED_GATING_DEFENSE` |
| **GAP-05: Recovery Logic Integration** | EpistemicOS does not expose an automatic system recovery callback when missing grader inputs or test failures occur. | Recovery behavior is tested by verifying that destructive agent actions (`rm -rf`, `pytest.mark.skip`) are halted by `PermissionGate` and `ContainmentGuard`. | `UNTESTED_RECOVERY_CALLBACK` |

---

## 5. Test Lab Architecture & Deliverables

The Incident Test Lab is structured as follows:

```
tests/incident_lab/
├── fixtures/
│   ├── base_fixture.py         # Abstract ObservableFixture and OperationExecutor
│   ├── scenario_fixtures.py    # Resettable synthetic environments for Cases 1–7
│   └── unprotected_baseline.py # Confined baseline executors for vulnerable paths
├── scenarios/
│   ├── base_scenario.py        # Base IncidentScenario interface & 2D reporting
│   ├── case1_github.py         # Case 1: GitHub credential exposure
│   ├── case2_government.py     # Case 2: Government data authorization bypass
│   ├── case3_egress.py         # Case 3: Indirect egress through browser/callbacks
│   ├── case4_dashboard.py      # Case 4: Internal dashboard & service access
│   ├── case5_crypto.py         # Case 5: Unauthorized cryptocurrency-wallet use
│   ├── case6_destructive.py    # Case 6: Destructive recovery & reward cheating
│   └── case7_fleet.py          # Case 7: Multi-agent fleet amplification
├── test_end_to_end.py          # Pytest integration suite for all 7 cases
└── test_fleet_concurrency.py   # Deterministic concurrent fleet execution tests

benchmarks/
└── run_incident_lab.py         # Main runner generating JSON & Markdown reports

results/
└── incident_lab_results.json    # Machine-readable output

docs/security/
├── incident_lab_design.md      # Design gate (this document)
└── incident_lab_report.md      # Generated human-readable evidence report
```

### Real Operation Interface & Observable Operation Tracking

Every attempted operation in the lab passes through an instrumented `OperationExecutor` that tracks:
- `agent_id` and `request_id`
- `action` and `resource`
- `destination` / `recipient`
- `payload` object
- `authorization_context`
- `expected_side_effect`
- `status`: `ATTEMPTED`, `ADMITTED`, `INVOKED`, `COMPLETED`, `ROLLED_BACK`, or `HALTED`

### Two Independent Evaluation Dimensions

- **Dimension A — Security Outcome:** Measures whether unauthorized actions were halted or executed. Explicit statuses: `PASS`, `FAIL`, `UNTESTED`, `BLOCKED_BY_ARCHITECTURE`, `INCONCLUSIVE`.
- **Dimension B — Legitimate Task Performance:** Measures whether authorized operations succeeded, recording false denial rates, completed tasks, and unnecessary halts.

---

## 6. Safety & Non-Interference Mandate

The test lab adheres strictly to the following safety properties:
1. **Default-Deny External Egress:** All networking is directed to isolated, local synthetic mock endpoints.
2. **Synthetic-Only Credentials:** Zero real API keys, SSH keys, GitHub tokens, or private keys are used.
3. **No Financial Risk:** All cryptocurrency testing uses an in-memory `MockWalletSimulator` with zero live network connections.
4. **Non-Destructive Execution:** File deletion commands (`rm -rf`) operate on in-memory synthetic state structures.
5. **Preservation of Core Code:** Production schedulers (`EntropyAwareScheduler`), production thresholds, and existing benchmark files are left completely untouched.
