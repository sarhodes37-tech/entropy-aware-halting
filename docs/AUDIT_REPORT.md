# EpistemicOS Adversarial Correctness Audit Report

## Executive Summary
An adversarial correctness audit of the EpistemicOS control pipeline was conducted. The audit traced execution paths from token/trajectory input through entropy estimation, gate evaluation, permission validation, halting, and audit receipt generation.

This report documents 11 confirmed defects, complete threat model & failure-mode matrices, severity-ranked findings with exact file and line references, minimal reproducible test cases (`tests/unit/test_adversarial_audit.py`), and a categorization distinguishing demonstrated vulnerabilities, plausible risks, and unsupported concerns.

---

## 1. Trace of Execution Path

1. **Ingress & Schema Normalization:**
   - Input payload enters `EpistemicOrchestrator.process_submission(raw_payload, context, trajectory_id)` (`epistemicos/core.py:164`).
   - Normalization via `CanonicalProblemRepresentation` (`epistemicos/core.py:77`). If schema fails, payload is masked and logged as `HALT`.
2. **Governance Gate Pipeline Evaluation:**
   - Iterates through registered gates in `self.gates` (`PermissionGate`, `EntropyGate`, `TriangulationGate`) via `_evaluate_gates` (`epistemicos/core.py:104`).
   - If a gate returns `action == GateAction.HALT`, execution halts, vector embeddings are revoked, and `HALT` event is logged to `TamperEvidentAuditTrail`.
3. **Entropy-Aware Scheduling Loop:**
   - Lower-level loop managed by `EntropyAwareScheduler.step(probabilities, cost, state)` (`epistemicos/scheduler.py:89`).
   - Computes Shannon entropy $H(P)$, updates utility $U$, and evaluates halting directives (`NEGATIVE_YIELD`, `OPTIMAL_CONVERGENCE`, `IRREDUCIBLE_UNCERTAINTY`).
4. **Tool Execution & Containment Guard:**
   - Active guardrails in `ContainmentGuard.wrap_tool_execution` (`epistemicos/containment.py:255`).
   - Checks ingress prompt patterns, egress hostnames/DNS, OS shell commands, and goal integrity.
5. **Audit Receipt & Egress:**
   - Successful execution commits vectors via `VectorHygieneManager.commit_trajectory` (`epistemicos/vector_hygiene.py:60`) and logs `INFO` event to `logs/audit.jsonl`.

---

## 2. Statistical Uncertainty Assumptions & Misconceptions

Throughout the control pipeline, statistical uncertainty (Shannon entropy, surprisal logprob Z-scores) is implicitly treated as proxy evidence for hallucination, prompt injection, or correctness:
- **`EntropyGate` (`epistemicos/gates.py:82`):** Assumes high token surprisal ($Z > z\_threshold$) indicates prompt injection or hallucination. Low surprisal is assumed safe.
- **`EntropyAwareScheduler` (`epistemicos/scheduler.py:118`):** Assumes low Shannon entropy ($H < 0.01$) over candidate probabilities represents "optimal convergence" / correctness. High entropy or rising entropy is treated as "negative yield" or failure.
- **`TriangulationGate` (`epistemicos/gates.py:228`):** Assumes statistical divergence from telemetry average represents "data washing".

---

## 3. Threat-Model and Failure-Mode Matrix

| Threat Vector / Failure Mode | Target Subsystem | Mechanism | Impact / Severity | Demonstrated / Plausible |
| :--- | :--- | :--- | :--- | :--- |
| **Fail-Open Gate Action Bypass** | `core.py:106` | Gates returning `GateAction.ROLLBACK` bypass `result.action == GateAction.HALT` check | Severe security bypass; dangerous actions permitted | **Demonstrated Vulnerability** |
| **Surprisal Warm-up Anomaly Bypass** | `models.py:121` | $Z$-score unconditionally forced to `0.0` for tokens at index 0 and 1 | Adversarial injection at prompt start completely bypasses detection | **Demonstrated Vulnerability** |
| **Non-Finite (`NaN`) Comparison Bypass** | `models.py:148`, `scheduler.py:69` | `NaN > threshold` evaluates to `False` in Python | Invalid/corrupted probability inputs bypass entropy gating | **Demonstrated Vulnerability** |
| **Silent Permit on Missing Context** | `gates.py:110, 240` | Missing `token_logprobs` or `heterogeneous_telemetry` returns `ALLOW` | Attackers suppress context/telemetry to disable security gates | **Demonstrated Vulnerability** |
| **Repetition Collapse False Negative** | `gates.py:82`, `models.py:110` | Repeated predictable tokens (`the the the...`) yield $Z = 0.0$ | Infinite generation loops pass as 100% safe | **Demonstrated Vulnerability** |
| **Valid Reasoning False Positive** | `gates.py:82`, `scheduler.py:118` | Prose-to-code/math syntax transitions produce surprisal jumps ($Z \gg 1.5$) | Legitimate code/math reasoning streams falsely halted | **Demonstrated Vulnerability** |
| **Rolling Window Ramping Evasion** | `models.py:110` | Linear/smooth surprisal increments adapt rolling std, keeping $Z < 2.85$ | Adversary increases surprisal by >500% without triggering halt | **Demonstrated Vulnerability** |
| **Scheduler State Leakage Across Requests** | `core.py:48`, `scheduler.py:53` | `self.scheduler` persistent across independent `process_step` requests | Step counts, costs, and utility leak between tenant requests | **Demonstrated Vulnerability** |
| **Permission Gate Textual Approximation Bypass** | `gates.py:160` | Checks metadata dict keys (`op`, `node`) rather than executable callable | Dangerous callables executed if metadata dictionary claims `op='read'` | **Demonstrated Vulnerability** |
| **Containment Guard Key Name Bypass** | `containment.py:255` | Checks only `kwargs['command']`, `kwargs['script']`, `kwargs['url']` | System escape when tool parameters use `args`, `cmd`, `target` | **Demonstrated Vulnerability** |
| **Permission Scope Key Omission Bypass** | `models.py:206` | Guards `if op:` and `if target:` skipped when keys are `None`/missing | Unrestricted operation or resource access on key omission | **Demonstrated Vulnerability** |

---

## 4. Detailed Severity-Ranked Findings

### 🔴 High Severity Findings

#### Finding 1: GateAction.ROLLBACK Treated as ALLOW in Core Orchestrator
- **Location:** `epistemicos/core.py`, Line 106
- **Description:** `_evaluate_gates` checks `if result.action == GateAction.HALT: return result`. If a gate returns `GateAction.ROLLBACK` (one of the three defined `GateAction` enum values), the check evaluates to `False`. The orchestrator treats the result as passed and executes the submission.
- **Proof of Concept:** `tests/unit/test_adversarial_audit.py::test_defect_1_rollback_treated_as_allow`
- **Proposed Fix:** Modify line 106 to check `if result.action in (GateAction.HALT, GateAction.ROLLBACK): return result` or `if result.action != GateAction.ALLOW: return result`.

#### Finding 2: Token Surprisal Warm-up Period Unconditionally Permits Anomalies at Index 0 and 1
- **Location:** `epistemicos/models.py`, Lines 121-124
- **Description:** In `TokenSurprisalSensor.compute_z_scores`, the loop unconditionally executes `if i < 2: z_scores.append(0.0)`. An extreme anomaly or prompt injection situated at token index 0 or 1 yields $Z = 0.0$ and is never flagged.
- **Proof of Concept:** `tests/unit/test_adversarial_audit.py::test_defect_2_surprisal_warmup_bypass`
- **Proposed Fix:** Evaluate initial token logprobs against a static prior surprisal baseline or global threshold when $i < 2$.

#### Finding 3: Missing Context / Telemetry Defaults to Silent ALLOW
- **Location:** `epistemicos/gates.py`, Lines 110, 240
- **Description:** If `token_logprobs` is missing from `context`, `EntropyGate` returns `GateAction.ALLOW` with reason `"NO_LOGPROBS_PROVIDED"`. Similarly, `TriangulationGate` returns `ALLOW` if telemetry is absent.
- **Proof of Concept:** `tests/unit/test_adversarial_audit.py::test_defect_4_missing_logprobs_silent_permit`
- **Proposed Fix:** Enforce a fail-closed configurable mode (`strict_mode=True`) where missing required security context yields `GateAction.HALT`.

#### Finding 4: Containment Guard Tool Inspection Bypassed via Non-Standard Parameter Names
- **Location:** `epistemicos/containment.py`, Lines 255-275
- **Description:** `wrap_tool_execution` checks specific dictionary keys: `command`, `script`, `url`, `endpoint`. If a tool signature uses `args`, `cmd`, `target`, `dest`, or positional parameters, containment checks are bypassed entirely.
- **Proof of Concept:** `tests/unit/test_adversarial_audit.py::test_defect_10_containment_guard_parameter_bypass`
- **Proposed Fix:** Inspect all positional and keyword string values in `args` and `kwargs`, regardless of parameter key names.

#### Finding 5: PermissionScope Validates Actions as Allowed when Keys are Omitted
- **Location:** `epistemicos/models.py`, Lines 206-215
- **Description:** `PermissionScope.validate_action` guards op and target checks with `if op:` and `if target:`. If an action payload omits `op` or `target`, the validation checks are skipped and return `True`.
- **Proof of Concept:** `tests/unit/test_adversarial_audit.py::test_defect_11_permission_scope_missing_key_bypass`
- **Proposed Fix:** Require explicit, non-empty `op` and `target` definitions in actions when scope boundaries are active.

---

### 🟡 Medium Severity Findings

#### Finding 6: Non-Finite (`NaN`) Logprobs Bypass Entropy and Surprisal Checks
- **Location:** `epistemicos/models.py`, Line 148; `epistemicos/scheduler.py`, Line 69
- **Description:** `NaN` surprisals produce `NaN` Z-scores. `NaN > threshold` evaluates to `False` in Python, so `flagged_count` is 0.
- **Proof of Concept:** `tests/unit/test_adversarial_audit.py::test_defect_3_nan_logprob_bypass`
- **Proposed Fix:** Explicitly validate input probabilities for `math.isnan()` and `math.isinf()` and reject non-finite values.

#### Finding 7: Smooth Surprisal Ramping Evades Sliding Window Detection
- **Location:** `epistemicos/models.py`, Lines 110-140
- **Description:** A gradual linear increase in token surprisals ($0.1, 0.4, 0.7, 1.0, \dots$) causes the sliding window mean and standard deviation to adapt proportionally, keeping $Z < 2.0$ throughout the ramp.
- **Proof of Concept:** `tests/unit/test_adversarial_audit.py::test_defect_7_rolling_window_ramping_evasion`
- **Proposed Fix:** Combine sliding window Z-score checks with absolute surprisal maximum ceilings.

#### Finding 8: Cross-Request State Leakage in Scheduler
- **Location:** `epistemicos/core.py`, Lines 48-52; `epistemicos/scheduler.py`, Lines 53-65
- **Description:** `self.scheduler` is created once on `EpistemicOrchestrator.__init__`. Calling `process_step` across independent user requests causes step indices, costs, and utility history to accumulate indefinitely.
- **Proof of Concept:** `tests/unit/test_adversarial_audit.py::test_defect_8_scheduler_state_leakage`
- **Proposed Fix:** Provide explicit `reset()` methods on `EntropyAwareScheduler` and call `reset()` per submission session in `core.py`.

#### Finding 9: Permission Gate Inspects Metadata Representations Instead of Executable Callables
- **Location:** `epistemicos/gates.py`, Lines 160-200
- **Description:** `PermissionGate` validates dictionary metadata (`op`, `node`) rather than inspecting underlying executable callables or AST representations.
- **Proof of Concept:** `tests/unit/test_adversarial_audit.py::test_defect_9_permission_gate_textual_approximation_bypass`
- **Proposed Fix:** Perform permission checking directly at tool execution wrappers on resolved target function signatures.

---

### 🔵 Low Severity / Qualitative Findings

#### Finding 10: False Negatives on Repetition Collapse
- **Location:** `epistemicos/gates.py`, Line 82; `epistemicos/models.py`, Line 110
- **Description:** Degenerate repetitive loops (`the the the...`) yield logprobs near 0.0 with zero variance ($Z = 0.0$), passing `EntropyGate`.
- **Proof of Concept:** `tests/unit/test_adversarial_audit.py::test_defect_5_repetition_collapse_false_negative`
- **Proposed Fix:** Integrate `calculate_trigram_repetition` into token stream inspection.

#### Finding 11: False Positives on Benign Reasoning / Syntax Shifts
- **Location:** `epistemicos/gates.py`, Line 82; `epistemicos/models.py`, Line 110
- **Description:** Transitioning from natural language to structured code/math syntax produces localized surprisal spikes ($Z \gg 1.5$), halting valid reasoning traces.
- **Proof of Concept:** `tests/unit/test_adversarial_audit.py::test_defect_6_valid_reasoning_false_positive`
- **Proposed Fix:** Apply AST persistence metrics (`calculate_ast_persistence`) to grant higher variance tolerance for syntactically valid code blocks.

---

## 5. Categorization of Risk Claims

### Demonstrated Vulnerabilities (Proven via Tests)
1. `GateAction.ROLLBACK` permitted as `ALLOW` in core orchestrator.
2. Token surprisal warm-up bypass at index 0 and 1.
3. `NaN` logprobs bypassing surprisal checks.
4. Missing logprobs/telemetry silently returning `ALLOW`.
5. Repetition collapse ($Z=0$) passing `EntropyGate`.
6. False positive halts on benign syntax shifts.
7. Smooth surprisal ramping evading sliding window Z-score detection.
8. Cross-request scheduler state leakage in orchestrator.
9. Permission gate inspecting metadata keys instead of callables.
10. Containment guard bypassed via non-standard parameter names.
11. Permission scope key omission bypass.

### Plausible Risks (Theoretical / Environment-Dependent)
1. Concurrent process race conditions in `TamperEvidentAuditTrail` when file locking (`fcntl`) is unavailable (Windows environments).
2. Memory degradation in `VectorHygieneManager._active_trajectories` if external orchestrator crashes without invoking scope exit handlers.

### Unsupported Concerns (Disproven / Out of Scope)
1. *Concern:* `_estimate_payload_size` causes recursion overflow on deeply nested payloads.
   - *Status:* Disproven. `_estimate_payload_size` uses an iterative stack-based DFS algorithm.
2. *Concern:* `ContainmentGuard` hostname extraction is vulnerable to standard `@` / `#` URL parsing bypasses.
   - *Status:* Disproven. `_extract_hostname_secure` explicitly strips unquoted `#`, `%23`, whitespace, and validates allowed hostname characters.

---

## Conclusion
The minimal reproducible test suite `tests/unit/test_adversarial_audit.py` programmatically verifies all 11 findings. System behavior was maintained without refactoring during the audit, as requested.
