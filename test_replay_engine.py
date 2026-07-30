import json
import random
from epistemicos.engine import EpistemicOrchestrator
from epistemicos.gates import EntropyGate, PermissionGate, CryptoAttestationGate
from epistemicos.cpr import CanonicalProblemRepresentation
from epistemicos.replay import ReplayEngine

def test_replay_determinism():
    print("Testing Replay Engine and Drift Detection...\n")

    # --- PHASE 1: THE HISTORICAL TRANSACTION ---
    # We set up the engine as it existed in the past
    priors_2026 = {"preferred": 0.5, "standard": 0.3, "substandard": 0.2}
    os_2026 = EpistemicOrchestrator(prior_probabilities=priors_2026)
    os_2026.register_gate("EntropyGate", EntropyGate(z_threshold=2.85))
    os_2026.register_gate("PermissionGate", PermissionGate(contract_model=CanonicalProblemRepresentation))

    # We use a mocked OCSP endpoint that won't flag our test key
    crypto_gate = CryptoAttestationGate(required_algorithm="ML-DSA", expiry_year=2030)
    crypto_gate._check_ocsp_revocation = lambda key_id: False
    os_2026.register_gate("CryptoAttestationGate", crypto_gate)

    mock_payload = {
        "policy_id": "POL-2026-AUDIT",
        "fleet_data": {"vehicle_count": 85, "operating_radius_miles": 1200.0, "hazard_class": "standard"}
    }
    proposed_actions = [{"action": {"op": "update_db", "node": "logistics_db", "status": "bound"}, "rollback": {"op": "none"}}]
    mock_likelihoods = {"preferred": 0.80, "standard": 0.15, "substandard": 0.05}
    safe_logprobs = [random.uniform(-0.05, -0.01) for _ in range(15)]
    valid_crypto_meta = {"algorithm": "ML-DSA", "key_id": "KEY-123-SECURE"}

    historical_result = os_2026.process_submission(
        raw_payload=mock_payload,
        likelihoods=mock_likelihoods,
        token_logprobs=safe_logprobs,
        proposed_actions=proposed_actions,
        crypto_metadata=valid_crypto_meta
    )
    historical_receipt = historical_result["receipt"]

    print("--- 1. HISTORICAL RECEIPT GENERATED ---")
    print(f"Status: {historical_receipt['status']}")
    print(f"Matrix: {historical_receipt['confidence_matrix']}\n")

    # --- PHASE 2: SYSTEM DRIFT OCCURS ---
    # Fast forward. The underlying risk model gets updated, changing the prior probabilities.
    # This simulates "Epistemic Drift".
    priors_2028 = {"preferred": 0.2, "standard": 0.5, "substandard": 0.3}
    os_2028 = EpistemicOrchestrator(prior_probabilities=priors_2028)
    os_2028.register_gate("EntropyGate", EntropyGate(z_threshold=2.85))
    os_2028.register_gate("PermissionGate", PermissionGate(contract_model=CanonicalProblemRepresentation))
    os_2028.register_gate("CryptoAttestationGate", crypto_gate)

    # --- PHASE 3: THE REPLAY AUDIT ---
    # The auditor plugs the historical receipt and exact inputs into the 2028 engine
    replay_engine = ReplayEngine(current_orchestrator=os_2028)

    attestation = replay_engine.replay_transaction(
        historical_receipt=historical_receipt,
        raw_payload=mock_payload,
        likelihoods=mock_likelihoods,
        token_logprobs=safe_logprobs,
        proposed_actions=proposed_actions
    )

    print("--- 2. REPLAY ATTESTATION RESULTS ---")
    print(json.dumps(attestation, indent=2))

if __name__ == "__main__":
    test_replay_determinism()
