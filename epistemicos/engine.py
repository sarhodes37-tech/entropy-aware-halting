from typing import Dict, Any, List, Optional
from epistemicos.beliefs import BayesianBeliefKernel
from epistemicos.gates import Gate
from epistemicos.receipts import ReceiptGenerator

class EpistemicOrchestrator:
    def __init__(self, prior_probabilities: Dict[str, float], gates: List[Gate]):
        self.belief_kernel = BayesianBeliefKernel(prior_probabilities)
        self.gates = gates

    def process_submission(
        self,
        raw_payload: dict,
        likelihoods: Dict[str, float],
        token_logprobs: List[float],
        proposed_actions: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:

        receipt_gen = ReceiptGenerator()
        transaction_id = raw_payload.get("policy_id", raw_payload.get("node_id", "UNKNOWN"))

        # 1. Bayesian Update
        updated_beliefs = self.belief_kernel.update_beliefs(likelihoods)
        receipt_gen.log_event("BeliefUpdated", {"posterior": updated_beliefs, "map": self.belief_kernel.get_map_estimate()})

        # 2. Stage Actions
        context = {"token_logprobs": token_logprobs, "proposed_actions": proposed_actions or []}
        for item in context["proposed_actions"]:
            receipt_gen.push_action(item.get("action", {}), item.get("rollback", {}))

        # 3. Process Gates (Choreography)
        all_gates_passed = True
        for gate in self.gates:
            gate_name = gate.__class__.__name__
            result = gate.evaluate(payload=raw_payload, context=context)
            receipt_gen.log_event(f"GateEvaluated:{gate_name}", result)

            if not result.get("passed", False):
                all_gates_passed = False
                break

        # 4. Lifecycle Control
        rollbacks_executed = []
        if all_gates_passed:
            receipt_gen.log_event("CommitIssued", {})
        else:
            rollbacks_executed = receipt_gen.rollback()

        receipt = receipt_gen.mint_receipt(transaction_id, success=all_gates_passed)

        return {
            "receipt": receipt,
            "rollbacks_executed": rollbacks_executed
        }
