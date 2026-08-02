import pytest
from epistemicos.models import (
    CanonicalProblemRepresentation,
    PermissionScope,
    BayesianBeliefKernel,
    TokenSurprisalSensor,
    EpistemicStatus
)

def test_permission_scope_quarantine():
    scope = PermissionScope(
        origin_subnet="10.240.1.5",
        allowed_operations=["read", "update_db"]
    )
    assert scope.is_quarantined_channel() is True
    
    # Mutating operation on quarantined subnet should be blocked
    action = {"op": "update_db", "node": "logistics_db"}
    assert scope.validate_action(action) is False

def test_bayesian_belief_kernel():
    kernel = BayesianBeliefKernel({"preferred": 0.5, "standard": 0.3, "substandard": 0.2})
    # Apply likelihoods favoring standard risk
    posteriors = kernel.update_beliefs({"preferred": 0.1, "standard": 0.9, "substandard": 0.2})
    
    assert posteriors["standard"] > posteriors["preferred"]
    assert kernel.get_map_estimate() == "standard"

def test_token_surprisal_sensor():
    sensor = TokenSurprisalSensor(z_threshold=2.0, window_size=5)
    # Normal logprobs followed by a massive anomaly drop
    logprobs = [-0.1, -0.2, -0.15, -0.1, -0.2, -5.5, -0.1]
    result = sensor.evaluate(logprobs)
    
    assert result["passed"] is False
    assert result["flagged_tokens"] > 0
    assert result["max_z_score"] > 2.0
