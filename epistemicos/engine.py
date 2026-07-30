from typing import Dict, Any, List, Optional
from epistemicos.beliefs import BayesianBeliefKernel
from epistemicos.gates import Gate
from epistemicos.receipts import ReceiptGenerator
from epistemicos.broker import kafka_mock

class EpistemicOrchestrator:
    def __init__(self, prior_probabilities: Dict[str, float]):
        self.belief_kernel = BayesianBeliefKernel(prior_probabilities)
        self.gates: Dict[str, Gate] = {}

    def register_gate(self, name: str, gate: Gate):
        """Plugin architecture: registers a new governance gate."""
        self.gates[name] = gate

    def process_submission(
        self,
        raw_payload: dict,
        likelihoods: Dict[str, float],
        token_logprobs: List[float],
        proposed_actions: Optional[List[Dict[str, Any]]] = None,
        crypto_metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:

        receipt_gen = ReceiptGenerator()
        transaction_id = raw_payload.get("policy_id", raw_payload.get("node_id", "UNKNOWN"))

        # 1. Epistemic Update
        updated_beliefs = self.belief_kernel.update_beliefs(likelihoods)
        epistemic_confidence = max(updated_beliefs.values())
        receipt_gen.log_event("BeliefUpdated", {"posterior": updated_beliefs, "map": self.belief_kernel.get_map_estimate()})

        # 2. Stage Actions
        context = {
            "token_logprobs": token_logprobs,
            "proposed_actions": proposed_actions or [],
            "cryptography": crypto_metadata or {"algorithm": "RSA-2048"},
            "heterogeneous_telemetry": raw_payload.get("heterogeneous_telemetry", []) # Optional feed for triangulation
        }
        for item in context["proposed_actions"]:
            receipt_gen.push_action(item.get("action", {}), item.get("rollback", {}))

        # 3. Process Plugin Gates
        all_gates_passed = True
        gate_confidences = {}

        for name, gate in self.gates.items():
            result = gate.evaluate(payload=raw_payload, context=context)
            receipt_gen.log_event(f"GateEvaluated:{name}", result)
            gate_confidences[name] = result.get("confidence", 0.0)

            if not result.get("passed", False):
                all_gates_passed = False

        # 4. Construct 4D Confidence Matrix
        confidence_matrix = {
            "epistemic": round(epistemic_confidence, 4),
            "semantic": gate_confidences.get("EntropyGate", 0.0),
            "execution": gate_confidences.get("PermissionGate", 0.0),
            "cryptographic": gate_confidences.get("CryptoAttestationGate", 0.0)
        }

        # 5. Lifecycle Control
        rollbacks_executed = []
        if all_gates_passed:
            receipt_gen.log_event("CommitIssued", {})
        else:
            rollbacks_executed = receipt_gen.rollback()

        receipt = receipt_gen.mint_receipt(transaction_id, success=all_gates_passed, confidence_matrix=confidence_matrix)

        # Publish asynchronously to decouple the hot path from slow blockchain logging
        kafka_mock.publish("receipts_topic", {
            "raw_payload": raw_payload,
            "receipt": receipt
        })

        return {
            "receipt": receipt,
            "rollbacks_executed": rollbacks_executed
        }
