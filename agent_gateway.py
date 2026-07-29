import hashlib
import logging
import time

class CrossAgentGateway:
    def __init__(self, entropy_threshold: float = 5.0, secret_key: str = "epistemic_internal_key"):
        self.entropy_threshold = entropy_threshold
        self.secret_key = secret_key
        logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
        self.logger = logging.getLogger("InterAgentGateway")

    def _generate_signature(self, payload: str, entropy_score: float, timestamp: float) -> str:
        data_string = f"{payload}|{entropy_score}|{timestamp}|{self.secret_key}"
        return hashlib.sha256(data_string.encode()).hexdigest()

    def generate_attestation(self, source_agent_id: str, target_agent_id: str, payload: str, entropy_score: float) -> dict:
        timestamp = time.time()
        signature = self._generate_signature(payload, entropy_score, timestamp)

        self.logger.info(f"Attestation generated for [{source_agent_id}] -> [{target_agent_id}].")
        return {
            "source": source_agent_id,
            "target": target_agent_id,
            "payload": payload,
            "metadata": {
                "entropy_score": entropy_score,
                "timestamp": timestamp,
                "signature": signature
            }
        }

    def verify_and_route(self, attestation: dict) -> str:
        try:
            metadata = attestation["metadata"]
            expected_sig = self._generate_signature(
                attestation["payload"], metadata["entropy_score"], metadata["timestamp"]
            )

            if expected_sig != metadata["signature"]:
                self.logger.error("Attestation REJECTED: Cryptographic signature mismatch.")
                raise ValueError("Routing Blocked: Invalid Signature.")

            if metadata["entropy_score"] > self.entropy_threshold:
                self.logger.error(f"Attestation REJECTED: Source entropy ({metadata['entropy_score']}) too high.")
                raise ValueError("Routing Blocked: Contagion Risk.")

            self.logger.info(f"Attestation VERIFIED. Routing payload to [{attestation['target']}].")
            return attestation["payload"]

        except KeyError as e:
            self.logger.error(f"Attestation REJECTED: Malformed packet missing {e}.")
            raise ValueError("Routing Blocked: Malformed Attestation.")
