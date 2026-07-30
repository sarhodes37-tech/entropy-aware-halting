from typing import Dict, Any, Tuple
from epistemicos.engine import EpistemicOrchestrator

class ReplayEngine:
    def __init__(self, current_orchestrator: EpistemicOrchestrator):
        """
        The Replay Engine requires a configured instance of the orchestrator
        to test historical transactions against current system logic.
        """
        self.orchestrator = current_orchestrator

    def _calculate_drift(self, historical_matrix: Dict[str, float], new_matrix: Dict[str, float]) -> Tuple[bool, Dict[str, float]]:
        """
        Calculates the absolute delta between historical and current confidence vectors.
        Returns a boolean indicating if drift occurred, and a dictionary of the deltas.
        """
        drift_detected = False
        deltas = {}

        for dimension in ["epistemic", "semantic", "execution", "cryptographic"]:
            hist_val = historical_matrix.get(dimension, 0.0)
            new_val = new_matrix.get(dimension, 0.0)

            # Calculate absolute difference
            delta = round(abs(hist_val - new_val), 4)
            deltas[dimension] = delta

            if delta > 0.0:
                drift_detected = True

        return drift_detected, deltas

    def replay_transaction(self, historical_receipt: Dict[str, Any], raw_payload: Dict[str, Any], likelihoods: Dict[str, float], token_logprobs: list, proposed_actions: list) -> Dict[str, Any]:
        """
        Rehydrates the transaction context and executes a sandbox run through the current orchestrator.
        """
        print(f"Initiating Replay for Transaction: {historical_receipt.get('transaction_id')}")

        # We inject the exact cryptographic metadata used historically to bypass live epoch decay issues during replay
        # The goal is to test the logic drift, not the passage of time.
        historical_crypto_meta = {"algorithm": "ML-DSA", "key_id": "REPLAY_BYPASS"}

        replay_result = self.orchestrator.process_submission(
            raw_payload=raw_payload,
            likelihoods=likelihoods,
            token_logprobs=token_logprobs,
            proposed_actions=proposed_actions,
            crypto_metadata=historical_crypto_meta
        )

        new_receipt = replay_result["receipt"]
        historical_matrix = historical_receipt.get("confidence_matrix", {})
        new_matrix = new_receipt.get("confidence_matrix", {})

        drift_detected, deltas = self._calculate_drift(historical_matrix, new_matrix)

        attestation = {
            "transaction_id": historical_receipt.get("transaction_id"),
            "replay_timestamp": new_receipt["event_log"][0]["timestamp"],
            "historical_status": historical_receipt.get("status"),
            "replay_status": new_receipt.get("status"),
            "drift_detected": drift_detected,
            "drift_deltas": deltas,
            "historical_matrix": historical_matrix,
            "replayed_matrix": new_matrix,
            "attestation_status": "FAILED_DUE_TO_DRIFT" if drift_detected else "VERIFIED_DETERMINISTIC"
        }

        return attestation
