import json
import random
from epistemicos.engine import EpistemicOrchestrator
from epistemicos.gates import EntropyGate, PermissionGate, CryptoAttestationGate
from epistemicos.cpr import CanonicalProblemRepresentation

def test_governance_os():
    print("Testing EpistemicOS Plugin Architecture & 4D Confidence Matrix...\n")

    # 1. Initialize the blank orchestrator
    priors = {"preferred": 0.5, "standard": 0.3, "substandard": 0.2}
    os = EpistemicOrchestrator(prior_probabilities=priors)

    # 2. Register plugins dynamically
    os.register_gate("EntropyGate", EntropyGate(z_threshold=2.85))
    os.register_gate("PermissionGate", PermissionGate(contract_model=CanonicalProblemRepresentation))

    # Simulate an enterprise enforcing Post-Quantum Cryptography standards
    os.register_gate("CryptoAttestationGate", CryptoAttestationGate(required_algorithm="ML-DSA", expiry_year=2030))

    # 3. Simulate an incoming transaction
    mock_payload = {
        "policy_id": "POL-2026-QUANTUM",
        "fleet_data": {"vehicle_count": 85, "operating_radius_miles": 1200.0, "hazard_class": "standard"}
    }
    proposed_actions = [{
        "action": {"op": "update_db", "node": "logistics_db", "status": "bound"},
        "rollback": {"op": "revert", "node": "logistics_db", "status": "pending"}
    }]

    mock_likelihoods = {"preferred": 0.80, "standard": 0.15, "substandard": 0.05}
    safe_logprobs = [random.uniform(-0.05, -0.01) for _ in range(15)]

    # Valid PQC metadata
    crypto_meta = {"algorithm": "ML-DSA"}

    result = os.process_submission(
        raw_payload=mock_payload,
        likelihoods=mock_likelihoods,
        token_logprobs=safe_logprobs,
        proposed_actions=proposed_actions,
        crypto_metadata=crypto_meta
    )

    print(json.dumps(result["receipt"], indent=2))

if __name__ == "__main__":
    test_governance_os()
