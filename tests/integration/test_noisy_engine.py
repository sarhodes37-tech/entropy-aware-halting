"""
Integration test for EpistemicOrchestrator under noisy/high-surprisal input.
Validates that EntropyGate halts execution and triggers Saga compensating rollbacks.
"""

from typing import Dict, Any, List
import pytest

from epistemicos.engine import EpistemicOrchestrator
from epistemicos.gates import EntropyGate, PermissionGate
from epistemicos.cpr import CanonicalProblemRepresentation


@pytest.fixture
def orchestrator_setup():
    """Initializes EpistemicOrchestrator with EntropyGate and PermissionGate."""
    priors = {"preferred": 0.5, "standard": 0.3, "substandard": 0.2}
    engine = EpistemicOrchestrator(prior_probabilities=priors)
    engine.register_gate("EntropyGate", EntropyGate(z_threshold=2.85))
    engine.register_gate("PermissionGate", PermissionGate(contract_model=CanonicalProblemRepresentation))
    return engine


@pytest.fixture
def mock_commercial_payload():
    return {
        "policy_id": "POL-2026-N99",
        "fleet_data": {
            "vehicle_count": 85,
            "operating_radius_miles": 1200.0,
            "loss_modifier": 1.45,
            "hazard_class": "severe",
            "garaging_states": ["TX", "CA", "AZ"]
        }
    }


@pytest.fixture
def saga_proposed_actions():
    return [
        {
            "action": {"op": "update_db", "node": "logistics_db", "status": "bound"},
            "rollback": {"op": "revert", "node": "logistics_db", "status": "pending"}
        },
        {
            "action": {"op": "issue_binder", "policy": "POL-2026-N99"},
            "rollback": {"op": "rescind_binder", "policy": "POL-2026-N99"}
        }
    ]


# =====================================================================
# Test Cases
# =====================================================================

def test_orchestrator_noisy_surprisal_halt_and_rollback(
    orchestrator_setup, mock_commercial_payload, saga_proposed_actions
):
    """
    Validates that high logprob surprisal triggers EntropyGate veto
    and executes all registered Saga compensating rollbacks.
    """
    engine = orchestrator_setup
    mock_likelihoods = {"preferred": 0.05, "standard": 0.25, "substandard": 0.70}

    # Deterministic baseline logprobs (20 low-entropy steps)
    deterministic_baseline = [-0.05] * 20
    # Inject extreme noise spike (high surprisal)
    noisy_logprobs = deterministic_baseline + [-12.5, -15.0, -11.8]

    result = engine.process_submission(
        raw_payload=mock_commercial_payload,
        likelihoods=mock_likelihoods,
        token_logprobs=noisy_logprobs,
        proposed_actions=saga_proposed_actions
    )

    # Core Assertions
    assert result["receipt"]["status"] != "COMMITTED"
    assert result["receipt"]["status"] in ("HALTED", "ROLLED_BACK")

    # Verify Saga compensating rollbacks executed in reverse order
    executed_rollbacks = result.get("rollbacks_executed", [])
    assert len(executed_rollbacks) == 2
    assert executed_rollbacks[0]["op"] == "rescind_binder"
    assert executed_rollbacks[1]["op"] == "revert"


def test_orchestrator_clean_logprobs_committed(
    orchestrator_setup, mock_commercial_payload, saga_proposed_actions
):
    """Validates that nominal logprobs without surprisal spikes commit successfully."""
    engine = orchestrator_setup
    mock_likelihoods = {"preferred": 0.80, "standard": 0.15, "substandard": 0.05}
    clean_logprobs = [-0.02] * 25

    result = engine.process_submission(
        raw_payload=mock_commercial_payload,
        likelihoods=mock_likelihoods,
        token_logprobs=clean_logprobs,
        proposed_actions=saga_proposed_actions
    )

    assert result["receipt"]["status"] == "COMMITTED"
    assert len(result.get("rollbacks_executed", [])) == 0
