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


def test_token_surprisal_sensor_warmup_period_anomaly():
    """Validates that initial token logprobs (index 0 and 1) are evaluated against baseline_prior_surprisal."""
    sensor = TokenSurprisalSensor(z_threshold=2.85, baseline_prior_surprisal=1.0, baseline_prior_std=1.0, std_floor=0.05)

    # Low surprisal initial tokens (-0.1 -> surprisal 0.1, z = (0.1 - 1.0)/1.0 = -0.9)
    z_scores_low = sensor.compute_z_scores([-0.1, -0.2])
    assert len(z_scores_low) == 2
    assert z_scores_low[0] < sensor.z_threshold
    assert z_scores_low[1] < sensor.z_threshold


def test_token_surprisal_extreme_anomaly_at_index_0():
    """Validates that extreme surprisal at token index 0 (during warm-up) is flagged."""
    sensor = TokenSurprisalSensor(z_threshold=2.85)
    result = sensor.evaluate([-25.0, -0.1, -0.1])
    assert result["passed"] is False
    assert result["flagged_tokens"] >= 1
    assert result["token_z_scores"][0] > sensor.z_threshold


def test_token_surprisal_extreme_anomaly_at_index_1():
    """Validates that extreme surprisal at token index 1 (during warm-up) is flagged."""
    sensor = TokenSurprisalSensor(z_threshold=2.85)
    result = sensor.evaluate([-0.1, -25.0, -0.1])
    assert result["passed"] is False
    assert result["flagged_tokens"] >= 1
    assert result["token_z_scores"][1] > sensor.z_threshold


def test_token_surprisal_extreme_anomaly_after_warmup():
    """Validates that extreme surprisal after the warm-up period (index >= 2) is flagged."""
    sensor = TokenSurprisalSensor(z_threshold=2.85)
    result = sensor.evaluate([-0.1, -0.1, -25.0, -0.1])
    assert result["passed"] is False
    assert result["flagged_tokens"] >= 1
    assert result["token_z_scores"][2] > sensor.z_threshold


def test_token_surprisal_ordinary_tokens_not_flagged():
    """Validates that ordinary, low-surprisal tokens throughout the sequence are not flagged."""
    sensor = TokenSurprisalSensor(z_threshold=2.85)
    result = sensor.evaluate([-0.1, -0.2, -0.15, -0.1, -0.2, -0.1])
    assert result["passed"] is True
    assert result["flagged_tokens"] == 0
    assert result["max_z_score"] < sensor.z_threshold


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
        origin_subnet="10.240.5.15",
        quarantine_subnets=["10.240."]
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


def test_permission_scope_validate_egress_valid_payload():
    """Validates egress allowed when payload size and row count are within limits."""
    scope = PermissionScope(max_payload_bytes=4096, max_row_count=10)
    payload = {"data": [1, 2, 3]}
    assert scope.validate_egress(payload) is True


def test_permission_scope_validate_egress_exceeds_payload_bytes():
    """Validates egress blocked when payload size exceeds max_payload_bytes."""
    scope = PermissionScope(max_payload_bytes=50, max_row_count=10)
    payload = {"data": "x" * 100}
    assert scope.validate_egress(payload) is False


def test_permission_scope_validate_egress_exceeds_row_count_list():
    """Validates egress blocked when nested list size exceeds max_row_count."""
    scope = PermissionScope(max_payload_bytes=4096, max_row_count=5)
    payload = {"data": [1, 2, 3, 4, 5, 6]}
    assert scope.validate_egress(payload) is False


def test_permission_scope_validate_egress_exceeds_row_count_dict():
    """Validates egress blocked when nested dict keys exceed max_row_count."""
    scope = PermissionScope(max_payload_bytes=4096, max_row_count=3)
    payload = {"a": 1, "b": {"c": 2, "d": 3, "e": 4, "f": 5}}
    assert scope.validate_egress(payload) is False


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

def test_token_surprisal_sensor_evaluate_integration_passed():
    """Validates the evaluate method using the real compute_z_scores when values pass."""
    sensor = TokenSurprisalSensor(z_threshold=2.85, window_size=10, std_floor=0.05)
    # Log probabilities representing normal, expected tokens (low surprisal/high probability)
    # Using logprobs close to 0, meaning very high probability.
    logprobs = [-0.1, -0.15, -0.2, -0.1, -0.15, -0.2, -0.1, -0.15, -0.2, -0.1, -0.1]

    result = sensor.evaluate(logprobs)

    assert result["passed"] is True
    assert result["flagged_tokens"] == 0
    assert result["max_z_score"] < 2.85
    assert len(result["token_z_scores"]) == len(logprobs)

def test_token_surprisal_sensor_evaluate_integration_flagged():
    """Validates the evaluate method using the real compute_z_scores when an anomaly occurs."""
    sensor = TokenSurprisalSensor(z_threshold=2.85, window_size=10, std_floor=0.05)
    # Log probabilities representing normal tokens followed by a highly surprising one (large negative logprob)
    logprobs = [-0.1, -0.15, -0.2, -0.1, -0.15, -0.2, -0.1, -0.15, -0.2, -0.1, -5.0]

    result = sensor.evaluate(logprobs)

    assert result["passed"] is False
    assert result["flagged_tokens"] > 0
    assert result["max_z_score"] > 2.85
    assert len(result["token_z_scores"]) == len(logprobs)


import json

@pytest.mark.parametrize("non_finite_val", [float('nan'), float('inf'), float('-inf')])
def test_token_surprisal_sensor_evaluate_non_finite_z_scores(monkeypatch, non_finite_val):
    """Validates that NaN, +inf, and -inf Z-scores are rejected as malformed numerical output and sanitized for JSON."""
    sensor = TokenSurprisalSensor(z_threshold=2.85)

    # Mock compute_z_scores to simulate a computation producing a non-finite Z-score
    monkeypatch.setattr(sensor, "compute_z_scores", lambda logprobs: [0.0, non_finite_val, 1.2])

    result = sensor.evaluate([-0.1, -0.2, -0.3])

    assert result["passed"] is False
    assert result["reason"] == "MALFORMED_NON_FINITE_LOGPROBS"
    assert "Derived Z-scores contain 1 non-finite value(s)" in result["error"]
    assert result["max_z_score"] == 0.0
    assert result["flagged_tokens"] == 3
    assert result["token_z_scores"] == [0.0, None, 1.2]
    # Ensure JSON serializability without allow_nan
    serialized = json.dumps(result, allow_nan=False)
    assert "null" in serialized


@pytest.mark.parametrize("non_finite_lp", [float('nan'), float('inf'), float('-inf')])
def test_token_surprisal_sensor_evaluate_malformed_non_finite_logprob(non_finite_lp):
    """Validates that NaN, +inf, and -inf input logprobs trigger ValueError handling and return failure."""
    sensor = TokenSurprisalSensor(z_threshold=2.85)
    result = sensor.evaluate([non_finite_lp, -0.5])

    assert result["passed"] is False
    assert result["reason"] == "MALFORMED_NON_FINITE_LOGPROBS"
    assert result["max_z_score"] == 0.0
    assert result["flagged_tokens"] == 2


def test_token_surprisal_ramping_evasion_blocked_by_ceiling():
    """Validates that smooth surprisal ramping that breaches max_surprisal_ceiling is flagged."""
    sensor = TokenSurprisalSensor(z_threshold=2.85, window_size=10, max_surprisal_ceiling=10.0)

    # Base low surprisals (around 1.0)
    base = [1.0, 1.5, 0.8, 1.4, 0.9, 1.6, 0.7, 1.3, 0.8, 1.2]
    # Gradually ramp surprisal up to 15.0 with step size 0.15 so Z-score stays low
    ramp = [1.2 + 0.15 * i for i in range(1, 100)]
    logprobs = [-x for x in (base + ramp)]

    result = sensor.evaluate(logprobs)
    assert result["passed"] is False
    assert result["flagged_tokens"] > 0


# ==========================================
# MODEL SERIALIZATION TESTS
# ==========================================
from datetime import datetime, timezone

def test_popperian_contract_serialization():
    """Validates PopperianContract dict/JSON serialization and round-trip deserialization."""
    contract = PopperianContract(
        claim_id="claim_001",
        target_metric="loss_ratio",
        falsification_threshold=5.0,
        comparison_operator=">",
        observation_window_days=30,
        falsification_impact_posterior=0.05
    )
    data_dict = contract.model_dump(mode="json")
    assert data_dict == {
        "claim_id": "claim_001",
        "target_metric": "loss_ratio",
        "falsification_threshold": 5.0,
        "comparison_operator": ">",
        "observation_window_days": 30,
        "falsification_impact_posterior": 0.05
    }

    json_str = contract.model_dump_json()
    parsed_json = json.loads(json_str)
    assert parsed_json["claim_id"] == "claim_001"
    assert parsed_json["falsification_threshold"] == 5.0

    restored = PopperianContract.model_validate_json(json_str)
    assert restored == contract


def test_bayes_factor_update_serialization():
    """Validates BayesFactorUpdate dict/JSON serialization including computed fields."""
    update = BayesFactorUpdate(
        evidence_id="ev_001",
        source_provenance=["log_a", "log_b"],
        p_evidence_given_hypothesis=0.8,
        p_evidence_given_not_hypothesis=0.2
    )
    data_dict = update.model_dump(mode="json")
    assert data_dict["evidence_id"] == "ev_001"
    assert data_dict["source_provenance"] == ["log_a", "log_b"]
    assert data_dict["bayes_factor"] == 4.0
    assert data_dict["bayes_factor_db"] == 6.02

    json_str = update.model_dump_json()
    parsed = json.loads(json_str)
    assert parsed["bayes_factor"] == 4.0

    restored = BayesFactorUpdate.model_validate_json(json_str)
    assert restored == update


def test_belief_object_nested_serialization():
    """Validates BeliefObject nested serialization with PopperianContract, BayesFactorUpdate list, EpistemicStatus enum, and datetime."""
    now = datetime.now(timezone.utc)
    contract = PopperianContract(
        claim_id="claim_100",
        target_metric="error_rate",
        falsification_threshold=0.01,
        comparison_operator=">=",
        observation_window_days=14,
        falsification_impact_posterior=0.0
    )
    update = BayesFactorUpdate(
        evidence_id="ev_100",
        source_provenance=["provenance_trace_1"],
        p_evidence_given_hypothesis=0.9,
        p_evidence_given_not_hypothesis=0.1
    )
    belief = BeliefObject(
        belief_id="bel_100",
        cpr_frame_id="cpr_100",
        assertion="Unicórniö test assertióñ with unicode",
        prior_probability=0.5,
        current_posterior=0.9,
        status=EpistemicStatus.CONFIRMED,
        evidence_ledger=[update],
        popp_contract=contract,
        created_at=now,
        ttl_days=90,
        invalidation_triggers=["trigger_alpha", "trigger_beta"]
    )

    data_dict = belief.model_dump(mode="json")
    assert data_dict["belief_id"] == "bel_100"
    assert data_dict["status"] == "CONFIRMED"
    assert isinstance(data_dict["created_at"], str)
    assert data_dict["popp_contract"]["claim_id"] == "claim_100"
    assert len(data_dict["evidence_ledger"]) == 1
    assert data_dict["evidence_ledger"][0]["bayes_factor"] == 9.0

    json_str = belief.model_dump_json()
    parsed = json.loads(json_str)
    assert parsed["status"] == "CONFIRMED"
    assert parsed["popp_contract"]["comparison_operator"] == ">="
    assert parsed["assertion"] == "Unicórniö test assertióñ with unicode"

    restored = BeliefObject.model_validate_json(json_str)
    assert restored.belief_id == belief.belief_id
    assert restored.status == EpistemicStatus.CONFIRMED
    assert restored.popp_contract == contract
    assert restored.evidence_ledger[0] == update


def test_permission_scope_serialization_and_defaults():
    """Validates PermissionScope serialization with custom subnets, defaults, and optional fields."""
    scope = PermissionScope(
        allowed_resources=["res_a", "res_b"],
        allowed_operations=["read"],
        expires_at=1700000000.0,
        max_attempts=5,
        attempt_count=2,
        origin_subnet="10.0.0.1",
        is_rmm_origin=False,
        quarantine_subnets=["10.240.", "172.16."]
    )

    data_dict = scope.model_dump(mode="json")
    assert data_dict["allowed_resources"] == ["res_a", "res_b"]
    assert data_dict["expires_at"] == 1700000000.0
    assert data_dict["origin_subnet"] == "10.0.0.1"
    assert data_dict["quarantine_subnets"] == ["10.240.", "172.16."]

    json_str = scope.model_dump_json()
    parsed = json.loads(json_str)
    assert parsed["max_attempts"] == 5

    restored = PermissionScope.model_validate_json(json_str)
    assert restored == scope


def test_cpr_nested_serialization_and_excluded_fields():
    """Validates CanonicalProblemRepresentation nested serialization, PermissionScope inclusion, and SENSITIVE_FIELDS exclusion."""
    scope = PermissionScope(
        allowed_resources=["logistics_db"],
        allowed_operations=["read"]
    )
    cpr = CanonicalProblemRepresentation(
        policy_id="POL-999",
        raw_payload={"user_id": 123, "api_key": "secret_key_123"},
        fleet_data={"vehicle_count": 200, "operating_radius_miles": 500, "loss_modifier": 1.1},
        risk_details={"loss_mod": 1.1},
        primary_metric=42.0,
        scope=scope
    )

    data_dict = cpr.model_dump(mode="json")
    assert data_dict["policy_id"] == "POL-999"
    assert data_dict["raw_payload"] == {"user_id": 123, "api_key": "secret_key_123"}
    assert data_dict["fleet_data"]["vehicle_count"] == 200
    assert data_dict["scope"]["allowed_resources"] == ["logistics_db"]
    # Verify SENSITIVE_FIELDS attribute is excluded from serialized data
    assert "SENSITIVE_FIELDS" not in data_dict

    json_str = cpr.model_dump_json()
    parsed = json.loads(json_str)
    assert parsed["primary_metric"] == 42.0
    assert "SENSITIVE_FIELDS" not in parsed

    restored = CanonicalProblemRepresentation.model_validate_json(json_str)
    assert restored.policy_id == cpr.policy_id
    assert restored.fleet_data == cpr.fleet_data
    assert restored.scope.allowed_resources == ["logistics_db"]
