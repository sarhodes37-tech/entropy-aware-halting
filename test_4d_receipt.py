import json
import random
from epistemicos.core import EpistemicOrchestrator
from epistemicos.gates import EntropyGate, PermissionGate, CryptoAttestationGate
from epistemicos.cpr import CanonicalProblemRepresentation

def test_governance_os():
    print("Testing EpistemicOS Plugin Architecture & Stateful Revocation...\n")

    priors = {"preferred": 0.5, "standard": 0.3, "substandard": 0.2}
    os = EpistemicOrchestrator(prior_probabilities=priors)

    os.register_gate("EntropyGate", EntropyGate(z_threshold=2.85))
    os.register_gate("PermissionGate", PermissionGate(contract_model=CanonicalProblemRepresentation))
    os.register_gate("CryptoAttestationGate", CryptoAttestationGate(required_algorithm="ML-DSA", expiry_year=2030))

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

    print("--- SCENARIO 1: VALID PQC KEY ---")
    valid_crypto_meta = {"algorithm": "ML-DSA", "key_id": "KEY-123-SECURE"}
    valid_result = os.process_submission(
        raw_payload=mock_payload,
        likelihoods=mock_likelihoods,
        token_logprobs=safe_logprobs,
        proposed_actions=proposed_actions,
        crypto_metadata=valid_crypto_meta
    )
    print(json.dumps(valid_result["receipt"], indent=2))

    print("\n--- SCENARIO 2: COMPROMISED PQC KEY (STATEFUL REVOCATION) ---")
    compromised_crypto_meta = {"algorithm": "ML-DSA", "key_id": "KEY-000-COMPROMISED"}
    compromised_result = os.process_submission(
        raw_payload=mock_payload,
        likelihoods=mock_likelihoods,
        token_logprobs=safe_logprobs,
        proposed_actions=proposed_actions,
        crypto_metadata=compromised_crypto_meta
    )
    print(json.dumps(compromised_result["receipt"], indent=2))

if __name__ == "__main__":
    test_governance_os()
