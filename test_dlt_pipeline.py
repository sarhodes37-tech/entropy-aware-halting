import random
from epistemicos.engine import EpistemicOrchestrator
from epistemicos.gates import EntropyGate, PermissionGate, CryptoAttestationGate
from epistemicos.cpr import CanonicalProblemRepresentation
from dlt_logger_service import DLTLoggerService

def test_full_dlt_pipeline():
    print("Testing Full DLT Pipeline (Hot Path -> Cold Path -> GDPR Delete)...\n")

    # 1. Instantiate the orchestrator and gates
    priors = {"preferred": 0.5, "standard": 0.3, "substandard": 0.2}
    os = EpistemicOrchestrator(prior_probabilities=priors)

    os.register_gate("EntropyGate", EntropyGate(z_threshold=2.85))
    os.register_gate("PermissionGate", PermissionGate(contract_model=CanonicalProblemRepresentation))

    crypto_gate = CryptoAttestationGate(required_algorithm="ML-DSA", expiry_year=2030)
    crypto_gate._check_ocsp_revocation = lambda key_id: False
    os.register_gate("CryptoAttestationGate", crypto_gate)

    # 2. Mock payload with PII
    transaction_id = "POL-2026-DLT-TEST"
    mock_payload = {
        "policy_id": transaction_id,
        "fleet_data": {"vehicle_count": 85, "operating_radius_miles": 1200.0, "hazard_class": "standard"},
        "pii": {"driver_names": ["John Doe", "Jane Smith"]}
    }
    proposed_actions = [{"action": {"op": "update_db", "node": "logistics_db", "status": "bound"}, "rollback": {"op": "none"}}]
    mock_likelihoods = {"preferred": 0.80, "standard": 0.15, "substandard": 0.05}
    safe_logprobs = [random.uniform(-0.05, -0.01) for _ in range(15)]
    valid_crypto_meta = {"algorithm": "ML-DSA", "key_id": "KEY-123-SECURE"}

    # 3. Hot Path: Process submission (publishes to broker)
    print("--- 1. EXECUTING HOT PATH ---")
    result = os.process_submission(
        raw_payload=mock_payload,
        likelihoods=mock_likelihoods,
        token_logprobs=safe_logprobs,
        proposed_actions=proposed_actions,
        crypto_metadata=valid_crypto_meta
    )
    print(f"Transaction Status: {result['receipt']['status']}")

    # 4. Cold Path: Process message queue
    print("\n--- 2. EXECUTING COLD PATH (DLT LOGGER) ---")
    logger_service = DLTLoggerService()
    logger_service.process_queue()

    # 5. GDPR Right to be Forgotten
    print("\n--- 3. GDPR DELETION REQUEST ---")
    logger_service.offchain_db.delete(transaction_id)

    # Verification
    if transaction_id not in logger_service.offchain_db._store:
        print(f"Verification: Payload for {transaction_id} successfully deleted from OffChain DB.")
    else:
        print(f"Verification: FAILED to delete payload for {transaction_id}.")

if __name__ == "__main__":
    test_full_dlt_pipeline()
