"""
Unit tests for epistemicos.models.
Targets edge cases in Popperian contracts, Bayesian updates, 
PermissionScope quarantine logic, and CPR serialization.
"""

import pytest
from epistemicos.models import (
    PopperianContract,
    BayesFactorUpdate,
    BeliefObject,
    PermissionScope,
    CanonicalProblemRepresentation,
    EpistemicStatus
)

# ==========================================
# POPPERIAN CONTRACT TESTS (Lines 115-123)
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
# BAYESIAN BELIEF KERNEL TESTS (Lines 137-142, 160-167, 170-174)
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
    assert update.bayes_factor_db == 6.02  # 10 * log10(4)


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

    # 1. Update belief (Lines 160-167)
    update = BayesFactorUpdate(
        evidence_id="ev_002",
        source_provenance=["telemetry"],
        p_evidence_given_hypothesis=0.9,
        p_evidence_given_not_hypothesis=0.1
    )
    belief.update_belief(update)
    assert belief.current_posterior == 0.9  # BF is 9.0, Prior odds 1.0 -> Posterior odds 9.0 -> Prob 0.9
    assert len(belief.evidence_ledger) == 1

    # 2. Check and Apply Falsification (Lines 170-174)
    # Threshold is > 200. We pass 250 to trigger falsification.
    falsified = belief.check_and_apply_falsification(250.0)
    assert falsified is True
    assert belief.status == EpistemicStatus.FALSIFIED
    assert belief.current_posterior == 0.01


# ==========================================
# PERMISSION SCOPE TESTS (Lines 198, 206-209)
# ==========================================
def test_permission_scope_quarantine_rmm_mutating_action():
    """Validates RMM origin flag blocks mutating operations like 'update_db'."""
    scope = PermissionScope(
        allowed_operations=["read", "update_db"],
        is_rmm_origin=True
    )
    
    # Should be true because of is_rmm_origin
    assert scope.is_quarantined_channel() is True
    
    # update_db is explicitly in the mutating_operations set
    assert scope.validate_action({"op": "update_db"}) is False
    
    # read is not mutating, should be allowed
    assert scope.validate_action({"op": "read"}) is True


def test_permission_scope_quarantine_subnet_mutating_action():
    """Validates subnet prefix matching blocks mutating operations."""
    scope = PermissionScope(
        allowed_operations=["read", "issue_binder"],
        origin_subnet="10.240.5.15"  # Matches quarantine prefix "10.240."
    )
    
    assert scope.is_quarantined_channel() is True
    assert scope.validate_action({"op": "issue_binder"}) is False


# ==========================================
# CPR SERIALIZATION TESTS (Lines 254-262)
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
    # Expected: [500/100, 2500/1000, 1.25]
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
    # Expected: [primary_metric, loss_ratio_3yr, 0.0] (Wait, code returns [metric, mod], let's check exact return length)
    # The code returns [self.primary_metric or 0.0, loss_mod]. 
    assert cpr.serialize_for_belief_kernel() == [0.85, 0.95]


def test_cpr_serialize_empty():
    """Validates default empty state serialization."""
    cpr = CanonicalProblemRepresentation(policy_id="POL-125")
    assert cpr.serialize_for_belief_kernel() == [0.0, 0.0, 0.0]
