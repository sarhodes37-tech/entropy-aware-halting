import json
import random
from epistemicos.engine import EpistemicOrchestrator
from epistemicos.gates import EntropyGate, PermissionGate, CryptoAttestationGate
from epistemicos.cpr import CanonicalProblemRepresentation
from epistemicos.replay import ReplayEngine

def test_replay():
    priors = {"preferred": 0.5, "standard": 0.3, "substandard": 0.2}
    os = EpistemicOrchestrator(prior_probabilities=priors)
    os.register_gate("EntropyGate", EntropyGate(z_threshold=2.85))
    os.register_gate("PermissionGate", PermissionGate(contract_model=CanonicalProblemRepresentation))
    os.register_gate("CryptoAttestationGate", CryptoAttestationGate(required_algorithm="ML-DSA", expiry_year=2030))

    replay = ReplayEngine(os)

    historical_receipt = {
        "transaction_id": "POL-TEST",
        "status": "COMMITTED",
        "confidence_matrix": {
            "epistemic": 0.8791,
            "semantic": 0.7769,
            "execution": 1.0,
            "cryptographic": 0.8
        }
    }

    mock_payload = {
        "policy_id": "POL-TEST",
        "fleet_data": {"vehicle_count": 85, "operating_radius_miles": 1200.0, "hazard_class": "standard"}
    }
    proposed_actions = [{
        "action": {"op": "update_db", "node": "logistics_db", "status": "bound"},
        "rollback": {"op": "revert", "node": "logistics_db", "status": "pending"}
    }]
    mock_likelihoods = {"preferred": 0.80, "standard": 0.15, "substandard": 0.05}
    safe_logprobs = [random.uniform(-0.05, -0.01) for _ in range(15)]

    res = replay.replay_transaction(historical_receipt, mock_payload, mock_likelihoods, safe_logprobs, proposed_actions)
    print(json.dumps(res, indent=2))

if __name__ == "__main__":
    test_replay()
