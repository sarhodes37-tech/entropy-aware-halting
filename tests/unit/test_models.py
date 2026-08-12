"""
Unit tests for epistemicos.models.
Targets edge cases in Popperian contracts, Bayesian updates, 
PermissionScope quarantine logic, CPR serialization, and Surprisal Sensors.
"""

import math
import pytest
from epistemicos.models import (
    PopperianContract,
    BayesFactorUpdate,
    BeliefObject,
    PermissionScope,
    CanonicalProblemRepresentation,
    EpistemicStatus,
    BayesianBeliefKernel,
    TokenSurprisalSensor,
    _estimate_payload_size
)

# ==========================================
# ESTIMATE PAYLOAD SIZE TESTS
# ==========================================
import sys

def test_estimate_payload_size_primitives():
    """Validates memory estimation for basic primitive types."""
    assert _estimate_payload_size(1) == sys.getsizeof(1)
    assert _estimate_payload_size("test") == sys.getsizeof("test")
    assert _estimate_payload_size(True) == sys.getsizeof(True)
    assert _estimate_payload_size(None) == sys.getsizeof(None)


def test_estimate_payload_size_collections():
    """Validates memory estimation for basic collections without nesting."""
    lst = [1, 2, 3]
    expected_lst = sys.getsizeof(lst) + sys.getsizeof(1) + sys.getsizeof(2) + sys.getsizeof(3)
    assert _estimate_payload_size(lst) == expected_lst

    tpl = (1, 2)
    expected_tpl = sys.getsizeof(tpl) + sys.getsizeof(1) + sys.getsizeof(2)
    assert _estimate_payload_size(tpl) == expected_tpl

    st = {1, 2}
    expected_st = sys.getsizeof(st) + sys.getsizeof(1) + sys.getsizeof(2)
    assert _estimate_payload_size(st) == expected_st


def test_estimate_payload_size_nested_dict():
    """Validates memory estimation for nested dictionaries."""
    d = {"a": 1, "b": {"c": 2}}

    expected_size = sys.getsizeof(d)
    expected_size += sys.getsizeof("a") + sys.getsizeof(1)
    expected_size += sys.getsizeof("b")

    inner_d = d["b"]
    expected_size += sys.getsizeof(inner_d)
    expected_size += sys.getsizeof("c") + sys.getsizeof(2)

    assert _estimate_payload_size(d) == expected_size


def test_estimate_payload_size_circular_reference():
    """Validates that circular references do not cause infinite recursion and are sized correctly."""
    lst = [1, 2]
    lst.append(lst) # Circular reference

    # Size should be size of list + size of 1 + size of 2 + 0 (since lst is already seen)
    expected_size = sys.getsizeof(lst) + sys.getsizeof(1) + sys.getsizeof(2)
    assert _estimate_payload_size(lst) == expected_size

    d = {"a": 1}
    d["self"] = d # Circular reference

    # Size should be size of d + size of "a" + size of 1 + size of "self" + 0
    expected_size_d = sys.getsizeof(d) + sys.getsizeof("a") + sys.getsizeof(1) + sys.getsizeof("self")
    assert _estimate_payload_size(d) == expected_size_d


# ==========================================
# TOKEN SURPRISAL SENSOR TESTS
# ==========================================
def test_token_surprisal_sensor_empty_logprobs():
    """Validates safe handling of empty telemetry streams."""
    sensor = TokenSurprisalSensor()
    assert sensor.compute_z_scores([]) == []


# ==========================================
# BAYESIAN BELIEF KERNEL TESTS
# ==========================================
def test_bayesian_belief_kernel_update_and_map():
    """Validates posterior normalization and MAP estimation in the core kernel."""
    priors = {"H_SAFE": 0.6, "H_COMPROMISED": 0.4}
    kernel = BayesianBeliefKernel(prior_probabilities=priors)

    # Evidence strongly suggests compromise
    likelihoods = {"H_SAFE": 0.2, "H_COMPROMISED": 0.8}
    
    posteriors = kernel.update_beliefs(likelihoods)
    
    # Unnormalized: H_SAFE = 0.6 * 0.2 = 0.12. H_COMPROMISED = 0.4 * 0.8 = 0.32
    # Total evidence = 0.44
    # Normalized: 0.12/0.44 = 0.2727..., 0.32/0.44 = 0.7272...
    assert math.isclose(posteriors["H_SAFE"], 0.27272727, rel_tol=1e-5)
    assert math.isclose(posteriors["H_COMPROMISED"], 0.72727272, rel_tol=1e-5)
    
    assert kernel.get_map_estimate() == "H_COMPROMISED"


# ==========================================
# POPPERIAN CONTRACT TESTS
# ==========================================
@pytest.mark.parametrize("operator, observed, threshold, expected", [
    (">", 10.0, 5.0, True),
    ("<", 3.0, 5.0, True),
    (">=", 5.0, 5.0, True),
    ("<=", 5.0, 5.0, True),
    ("==", 5.0, 5.0, True),
    ("!=", 6.0, 5.0, True),
    (">", 4.0, 5.0, False),
    ("==", 6.0, 5.0, False),
])
def test_popperian_contract_evaluate_falsification(operator, observed, threshold, expected):
    """Validates all mathematical operators in the falsification contract."""
    contract = PopperianContract(
        claim_id="claim_001",
        target_metric="loss_ratio",
        falsification_threshold=threshold,
        comparison_operator=operator,
        observation_window_days=30,
        falsification_impact_posterior=0.1
    )
    assert contract.evaluate_falsification(observed) == expected


def test_popperian_contract_unsupported_operator():
    """Validates error handling for invalid operators."""
    contract = PopperianContract(
        claim_id="claim_002",
        target_metric="loss_ratio",
        falsification_threshold=5.0,
        comparison_operator=">>",
        observation_window_days=30
    )
    with pytest.raises(ValueError, match="Unsupported comparison operator"):
        contract.evaluate_falsification(10.0)


# ==========================================
# BELIEF OBJECT TESTS
# ==========================================
def test_bayes_factor_update_computation():
    """Validates the Pydantic validator computes Bayes factors correctly."""
    update = BayesFactorUpdate(
        evidence_id="ev_001",
        source_provenance=["log_a"],
        p_evidence_given_hypothesis=0.8,
        p_evidence_given_not_hypothesis=0.2
    )
    assert update.bayes_factor == 4.0
    assert update.bayes_factor_db == 6.02


def test_belief_object_update_and_falsify():
    """Validates posterior math and status state transitions."""
    contract = PopperianContract(
        claim_id="claim_003",
        target_metric="latency",
        falsification_threshold=200.0,
        comparison_operator=">",
        observation_window_days=7,
        falsification_impact_posterior=0.01
    )
    
    belief = BeliefObject(
        belief_id="bel_001",
        cpr_frame_id="cpr_001",
        assertion="System is stable",
        prior_probability=0.5,
        current_posterior=0.5,
        popp_contract=contract
    )

    update = BayesFactorUpdate(
        evidence_id="ev_002",
        source_provenance=["telemetry"],
        p_evidence_given_hypothesis=0.9,
        p_evidence_given_not_hypothesis=0.1
    )
    belief.update_belief(update)
    assert belief.current_posterior == 0.9
    assert len(belief.evidence_ledger) == 1

    # Apply Falsification (True branch)
    falsified = belief.check_and_apply_falsification(250.0)
    assert falsified is True
    assert belief.status == EpistemicStatus.FALSIFIED
    assert belief.current_posterior == 0.01


def test_belief_object_falsification_safe_bounds():
    """Validates the negative branch when observation remains within safe parameters."""
    contract = PopperianContract(
        claim_id="claim_004",
        target_metric="latency",
        falsification_threshold=200.0,
        comparison_operator=">",
        observation_window_days=7
    )
    belief = BeliefObject(
        belief_id="bel_002",
        cpr_frame_id="cpr_002",
        assertion="System stable",
        prior_probability=0.5,
        current_posterior=0.5,
        popp_contract=contract
    )
    
    # Metric is 150 (Safe, does not breach > 200 threshold)
    falsified = belief.check_and_apply_falsification(150.0)
    assert falsified is False
    assert belief.status == EpistemicStatus.UNVERIFIED


# ==========================================
# PERMISSION SCOPE TESTS
# ==========================================
def test_permission_scope_quarantine_rmm_mutating_action():
    """Validates RMM origin flag blocks mutating operations like 'update_db'."""
    scope = PermissionScope(
        allowed_operations=["read", "update_db"],
        is_rmm_origin=True
    )
    assert scope.is_quarantined_channel() is True
    assert scope.validate_action({"op": "update_db"}) is False
    assert scope.validate_action({"op": "read"}) is True


def test_permission_scope_quarantine_subnet_mutating_action():
    """Validates subnet prefix matching blocks mutating operations."""
    scope = PermissionScope(
        allowed_operations=["read", "issue_binder"],
        origin_subnet="10.240.5.15"
    )
    assert scope.is_quarantined_channel() is True
    assert scope.validate_action({"op": "issue_binder"}) is False


def test_permission_scope_clean_internal_subnet():
    """Validates safe internal subnets bypass the quarantine lock."""
    scope = PermissionScope(
        allowed_operations=["read", "issue_binder"],
        origin_subnet="192.168.1.150"
    )
    assert scope.is_quarantined_channel() is False
    assert scope.validate_action({"op": "issue_binder"}) is True


# ==========================================
# CPR SERIALIZATION TESTS
# ==========================================
def test_cpr_serialize_fleet_data():
    """Validates metric extraction when fleet_data is present."""
    cpr = CanonicalProblemRepresentation(
        policy_id="POL-123",
        fleet_data={
            "vehicle_count": 500,
            "operating_radius_miles": 2500,
            "loss_modifier": 1.25
        }
    )
    assert cpr.serialize_for_belief_kernel() == [5.0, 2.5, 1.25]


def test_cpr_serialize_risk_details():
    """Validates metric extraction when risk_details is present (fallback)."""
    cpr = CanonicalProblemRepresentation(
        policy_id="POL-124",
        primary_metric=0.85,
        risk_details={
            "loss_ratio_3yr": 0.95
        }
    )
    assert cpr.serialize_for_belief_kernel() == [0.85, 0.95]


def test_cpr_serialize_empty():
    """Validates default empty state serialization."""
    cpr = CanonicalProblemRepresentation(policy_id="POL-125")
    assert cpr.serialize_for_belief_kernel() == [0.0, 0.0, 0.0]
