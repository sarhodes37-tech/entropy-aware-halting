import json
import random
from epistemicos.engine import EpistemicEngine

def test_noisy_integration():
    # Define our prior risk probabilities
    priors = {"preferred": 0.5, "standard": 0.3, "substandard": 0.2}
    engine = EpistemicEngine(prior_probabilities=priors)

    # Proposed actions and their corresponding JSON Patch rollbacks
    proposed_actions = [
        {
            "action": {"op": "update_db", "node": "logistics_db", "status": "bound"},
            "rollback": {"op": "revert", "node": "logistics_db", "status": "pending"}
        },
        {
            "action": {"op": "issue_binder", "policy": "POL-2026-N99"},
            "rollback": {"op": "rescind_binder", "policy": "POL-2026-N99"}
        }
    ]

    # Mock payload simulating a complex commercial logistics risk
    mock_payload = {
        "policy_id": "POL-2026-N99",
        "fleet_data": {
            "vehicle_count": 85,
            "operating_radius_miles": 1200.0,
            "loss_modifier": 1.45,
            "hazard_class": "severe",
            "garaging_states": ["TX", "CA", "AZ"]
        }
    }

    # Likelihoods leaning toward a substandard risk
    mock_likelihoods = {"preferred": 0.05, "standard": 0.25, "substandard": 0.70}

    # Generate a baseline of 20 "safe" tokens (low entropy)
    baseline_logprobs = [random.uniform(-0.1, -0.01) for _ in range(20)]

    # Inject extreme noise (high entropy spike) to trigger the blowout preventer
    noisy_logprobs = baseline_logprobs + [-12.5, -15.0, -11.8]

    print("Testing Engine with Native Saga Integration (Noisy Input)...\n")
    result = engine.process_submission(
        raw_payload=mock_payload,
        likelihoods=mock_likelihoods,
        token_logprobs=noisy_logprobs,
        proposed_actions=proposed_actions
    )

    print(json.dumps(result, indent=2))

    if result["execution_approved"]:
        print("\n🚨 FAIL: Execution approved despite heavy noise!")
    else:
        print(f"\n🛑 SUCCESS: Execution Halted. Max Z-Score: {result['attestation_gate']['max_z_score']:.2f}")
        print(f"🔄 Rollbacks Executed: {len(result['rollbacks_executed'])}")
        print("Rollback sequence:")
        print(json.dumps(result['rollbacks_executed'], indent=2))

if __name__ == "__main__":
    test_noisy_integration()
