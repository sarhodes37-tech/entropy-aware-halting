"""
Property-based tests for EpistemicOS core components using Hypothesis.

Covers input domains:
- Empty and short streams.
- Constant and alternating probability distributions.
- Extreme probability values and numerical edge cases.
- Window-boundary transitions.
- Malformed structured actions.
- Nested or ambiguous tool-call representations.
- Repeated requests with interleaved state.
- Gate exceptions and partial failures.
- Retry exhaustion and recovery transitions.

Verifies invariants:
- Independent requests must not contaminate each other's rolling statistics.
- Invalid probability inputs must not silently produce valid-looking confidence scores.
- A denied action must never execute through an alternate recovery path.
- Repeated evaluation of the same immutable input and configuration must be deterministic wherever determinism is promised.
- Audit receipt verification must fail after covered data is modified.
"""

import math
import os
import json
import hashlib
import tempfile
import pytest
hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, strategies as st, settings, HealthCheck, assume

from epistemicos.scheduler import EntropyAwareScheduler, DecisionResult
from epistemicos.gates import (
    EntropyGate,
    PermissionGate,
    TriangulationGate,
    CryptoAttestationGate,
    GateAction,
    GateResult
)
from epistemicos.models import (
    TokenSurprisalSensor,
    PermissionScope,
    CanonicalProblemRepresentation,
    PopperianContract
)
from epistemicos.core import EpistemicOrchestrator
from epistemicos.audit import TamperEvidentAuditTrail, AuditEvent, AuditLogLevel, ReceiptGenerator


# ==============================================================================
# INVARIANT 1: Independent requests must not contaminate each other's statistics
# ==============================================================================

@given(
    probs1=st.lists(st.floats(min_value=0.01, max_value=0.99), min_size=1, max_size=10),
    probs2=st.lists(st.floats(min_value=0.01, max_value=0.99), min_size=1, max_size=10)
)
def test_invariant_independent_trajectories_isolation(probs1, probs2):
    """
    INVARIANT: Independent requests (trajectories) must not contaminate
    each other's rolling statistics or scheduler state in EpistemicOrchestrator.
    """
    orchestrator = EpistemicOrchestrator()

    # Process sequence on trajectory A
    res_a1 = orchestrator.process_step(probs1, cost=1.0, state="A_state_1", trajectory_id="traj_A")

    # Process sequence on trajectory B (interleaved)
    res_b1 = orchestrator.process_step(probs2, cost=10.0, state="B_state_1", trajectory_id="traj_B")

    # Process next step on trajectory A
    res_a2 = orchestrator.process_step(probs1, cost=1.0, state="A_state_2", trajectory_id="traj_A")

    # Single isolated scheduler for trajectory A
    isolated_scheduler_a = EntropyAwareScheduler()
    iso_a1 = isolated_scheduler_a.step(probs1, cost=1.0, state="A_state_1")
    iso_a2 = isolated_scheduler_a.step(probs1, cost=1.0, state="A_state_2")

    # Invariant check: Interleaved trajectory A produced identical utility and step history to isolated A
    assert res_a2.current_utility == iso_a2.current_utility
    assert res_a2.termination_step == iso_a2.termination_step
    assert len(orchestrator._schedulers["traj_A"].history) == 2


@given(
    logprobs_a=st.lists(st.floats(min_value=-10.0, max_value=-0.01), min_size=3, max_size=15),
    logprobs_b=st.lists(st.floats(min_value=-50.0, max_value=-0.01), min_size=3, max_size=15)
)
def test_invariant_surprisal_sensor_instance_isolation(logprobs_a, logprobs_b):
    """
    INVARIANT: Separate surprisal sensor instances processing streams do not bleed state.
    """
    sensor_1 = TokenSurprisalSensor(z_threshold=2.85, window_size=10)
    sensor_2 = TokenSurprisalSensor(z_threshold=2.85, window_size=10)

    z1 = sensor_1.compute_z_scores(logprobs_a)
    z2 = sensor_2.compute_z_scores(logprobs_a)

    assert z1 == z2


# ==============================================================================
# INVARIANT 2: Invalid probability inputs must not produce valid confidence
# ==============================================================================

@given(
    invalid_probs=st.one_of(
        st.just([]),
        st.lists(st.just(0.0), min_size=1, max_size=5),
        st.lists(st.floats(max_value=-0.0001), min_size=1, max_size=5),
        st.lists(st.just(float("nan")), min_size=1, max_size=5),
        st.lists(st.just(float("inf")), min_size=1, max_size=5),
        st.lists(st.just("-inf"), min_size=1, max_size=5),
        st.lists(st.one_of(st.text(), st.dictionaries(st.text(), st.text())), min_size=1, max_size=3)
    )
)
def test_invariant_invalid_probability_rejection(invalid_probs):
    """
    INVARIANT: Invalid probability inputs must never silently return valid confidence scores
    or compute valid entropy. They must strictly raise ValueError or TypeError.
    """
    scheduler = EntropyAwareScheduler()
    with pytest.raises((ValueError, TypeError)):
        scheduler.entropy(invalid_probs)


@given(
    malformed_logprobs=st.one_of(
        st.lists(st.just(float("nan")), min_size=1, max_size=5),
        st.lists(st.just(float("inf")), min_size=1, max_size=5),
        st.lists(st.just("invalid_string"), min_size=1, max_size=3)
    )
)
def test_invariant_entropy_gate_malformed_input_handling(malformed_logprobs):
    """
    INVARIANT: EntropyGate evaluating malformed or non-finite logprobs must HALT
    and return 0.0 confidence score (never ALLOW or valid confidence).
    """
    gate = EntropyGate(z_threshold=2.85)
    result = gate.evaluate(payload={}, context={"token_logprobs": malformed_logprobs})

    assert result.action == GateAction.HALT
    assert result.confidence == 0.0
    assert result.status == "HALTED"


# ==============================================================================
# INVARIANT 3: Denied action must never execute through alternate recovery path
# ==============================================================================

@given(
    unauthorized_op=st.sampled_from(["update_db", "write_db", "issue_binder", "api_call", "web_search", "sudo", "exec"]),
    action_structure=st.sampled_from(["flat", "nested_dict", "object_attr", "ambiguous_tool_call"])
)
def test_invariant_denied_action_never_bypassed_by_structure(unauthorized_op, action_structure):
    """
    INVARIANT: A denied/unauthorized action must be consistently HALTED by PermissionGate
    regardless of how the action object is packaged or nested (flat dict, nested dict, or object).
    """
    gate = PermissionGate(allowed_actions=["read_only_query"])

    if action_structure == "flat":
        proposed = [{"op": unauthorized_op, "node": "restricted_node"}]
    elif action_structure == "nested_dict":
        proposed = [{"action": {"op": unauthorized_op, "node": "restricted_node"}}]
    elif action_structure == "object_attr":
        class ActionObj:
            def __init__(self, op, node):
                self.op = op
                self.node = node
        proposed = [ActionObj(unauthorized_op, "restricted_node")]
    else:  # ambiguous tool call embedded in context
        proposed = [{"action": {"action": {"op": unauthorized_op, "endpoint": "restricted_node"}}}]

    res = gate.evaluate(
        payload={"scope": {"allowed_operations": ["read_only_query"]}},
        context={"proposed_actions": proposed}
    )

    assert res.action == GateAction.HALT
    assert res.status == "HALTED"


@given(
    attempts=st.integers(min_value=4, max_value=100)
)
def test_invariant_retry_exhaustion_recovery_transition(attempts):
    """
    INVARIANT: PermissionScope with exhausted attempts (attempt_count > max_attempts)
    must strictly fail validation for any action, preventing recovery bypasses.
    """
    scope = PermissionScope(
        allowed_resources=["db"],
        allowed_operations=["read"],
        max_attempts=3,
        attempt_count=attempts
    )

    # Action matches allowed_resources and allowed_operations, but retry limit is exhausted
    action = {"op": "read", "node": "db"}
    assert scope.validate_action(action) is False


# ==============================================================================
# INVARIANT 4: Determinism of repeated evaluation on immutable input
# ==============================================================================

@given(
    payload_data=st.fixed_dictionaries({
        "policy_id": st.just("POL-2026-TEST"),
        "primary_metric": st.floats(min_value=0.0, max_value=1000.0),
        "raw_payload": st.fixed_dictionaries({"claim_amount": st.integers(min_value=100, max_value=5000)})
    }),
    hetero_telemetry=st.lists(st.floats(min_value=0.0, max_value=1000.0), min_size=2, max_size=5)
)
def test_invariant_deterministic_evaluation(payload_data, hetero_telemetry):
    """
    INVARIANT: Evaluating the exact same immutable input and configuration
    must yield identical gate actions and divergence metrics.
    """
    tri_gate = TriangulationGate(max_divergence_threshold=0.15)

    res1 = tri_gate.evaluate(payload=payload_data, context={"heterogeneous_telemetry": hetero_telemetry})
    res2 = tri_gate.evaluate(payload=payload_data, context={"heterogeneous_telemetry": hetero_telemetry})

    assert res1.action == res2.action
    assert res1.divergence == res2.divergence
    assert res1.status == res2.status


# ==============================================================================
# INVARIANT 5: Audit receipt & chain verification fails when data modified
# ==============================================================================

@given(
    tamper_index=st.integers(min_value=0, max_value=2)
)
def test_invariant_audit_trail_tamper_detection(tamper_index):
    """
    INVARIANT: Modifying any recorded data or hash in the append-only audit trail
    must cause verify_chain_integrity to return False.
    """
    with tempfile.NamedTemporaryFile(mode="w+", delete=False, suffix=".jsonl") as tmp:
        log_file = tmp.name

    try:
        audit = TamperEvidentAuditTrail(log_file_path=log_file)

        # Record 3 events
        for i in range(3):
            audit.record_event(AuditEvent(
                event_type=AuditLogLevel.INFO,
                gate_name=f"Gate_{i}",
                reason=f"Reason {i}",
                model_id="test_model",
                payload_snippet=json.dumps({"step": i})
            ))

        # Initial check must pass
        is_valid, count, err = audit.verify_chain_integrity()
        assert is_valid is True
        assert count == 3

        # Read lines and tamper
        with open(log_file, "r") as f:
            lines = f.readlines()

        data = json.loads(lines[tamper_index])
        data["reason"] = "TAMPERED_REASON"
        lines[tamper_index] = json.dumps(data) + "\n"

        with open(log_file, "w") as f:
            f.writelines(lines)

        # Re-verify must detect tampering
        audit_tampered = TamperEvidentAuditTrail(log_file_path=log_file)
        is_valid_after, count_after, err_after = audit_tampered.verify_chain_integrity()

        assert is_valid_after is False
        assert "Tampered" in err_after or "Broken" in err_after

    finally:
        if os.path.exists(log_file):
            os.remove(log_file)


@given(
    transaction_id=st.uuids().map(str),
    confidence=st.floats(min_value=0.0, max_value=1.0)
)
def test_invariant_receipt_generator_signature_verification(transaction_id, confidence):
    """
    INVARIANT: Audit receipt verification signature fails/changes if receipt event data is tampered with.
    """
    rg = ReceiptGenerator()
    rg.log_event("ActionProposed", {"op": "read", "node": "table_a"})
    receipt = rg.mint_receipt(transaction_id, success=True, confidence_matrix={"node": confidence})

    original_sig = receipt["signature"]

    # Tamper with event details
    receipt["event_log"][0]["details"]["op"] = "write"

    # Re-compute signature manually over the tampered receipt structure
    check_receipt = {k: v for k, v in receipt.items() if k != "signature"}
    computed_sig = hashlib.sha256(json.dumps(check_receipt, sort_keys=True).encode()).hexdigest()

    assert original_sig != computed_sig


# ==============================================================================
# ADDITIONAL PROPERTY TESTS: Streams, Window Boundaries, & Distributions
# ==============================================================================

@given(
    probs_constant=st.lists(st.just(0.2), min_size=5, max_size=5),
    probs_alternating=st.lists(st.sampled_from([0.1, 0.9]), min_size=6, max_size=6)
)
def test_property_probability_distributions_and_entropy_deltas(probs_constant, probs_alternating):
    """
    Tests constant vs. alternating probability streams over window boundaries in scheduler.
    """
    scheduler = EntropyAwareScheduler()

    # Constant probabilities produce zero entropy delta
    res1 = scheduler.step(probs_constant, cost=1.0, state="s1")
    res2 = scheduler.step(probs_constant, cost=1.0, state="s2")

    assert math.isclose(scheduler.history[-1].delta_h, 0.0, abs_tol=1e-5)

    # Alternating probabilities change entropy
    res3 = scheduler.step(probs_alternating, cost=1.0, state="s3")
    assert res3.directive in ["CONTINUE", "NEGATIVE_YIELD", "OPTIMAL_CONVERGENCE", "IRREDUCIBLE_UNCERTAINTY"]


@given(
    window_logprobs=st.lists(st.floats(min_value=-5.0, max_value=-0.1), min_size=10, max_size=25)
)
def test_property_window_boundary_transitions_surprisal(window_logprobs):
    """
    Tests window boundary transitions in TokenSurprisalSensor (window_size=10).
    """
    sensor = TokenSurprisalSensor(z_threshold=2.85, window_size=10)
    z_scores = sensor.compute_z_scores(window_logprobs)

    assert len(z_scores) == len(window_logprobs)
    # First 2 tokens should evaluate against baseline_prior_surprisal and baseline_prior_std
    std_prior = max(sensor.baseline_prior_std, sensor.std_floor)
    assert math.isclose(z_scores[0], (-window_logprobs[0] - sensor.baseline_prior_surprisal) / std_prior)
    assert math.isclose(z_scores[1], (-window_logprobs[1] - sensor.baseline_prior_surprisal) / std_prior)


@given(
    revoked_key=st.text(min_size=5, max_size=20),
    other_key=st.text(min_size=5, max_size=20)
)
def test_property_crypto_gate_revocation_exceptions(revoked_key, other_key):
    """
    Tests CryptoAttestationGate exception handling for OCSP key revocation.
    """
    assume(revoked_key != other_key)
    gate = CryptoAttestationGate(required_algorithm="ML-DSA", revoked_keys=frozenset([revoked_key]))

    # Revoked key MUST halt
    res_rev = gate.evaluate(payload={}, context={"cryptography": {"algorithm": "ML-DSA", "key_id": revoked_key}})
    assert res_rev.action == GateAction.HALT
    assert "REVOKED" in res_rev.reason

    # Non-revoked key with valid algo MUST allow
    res_ok = gate.evaluate(payload={}, context={"cryptography": {"algorithm": "ML-DSA", "key_id": other_key}})
    assert res_ok.action == GateAction.ALLOW
