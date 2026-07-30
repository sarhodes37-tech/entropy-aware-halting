from typing import Dict, Any, List, Optional
from epistemicos.cpr import CanonicalProblemRepresentation
from epistemicos.beliefs import BayesianBeliefKernel
from epistemicos.entropy import EntropyAttestationGate
from epistemicos.saga import ActionBuffer

class EpistemicEngine:
    def __init__(self, prior_probabilities: Dict[str, float], z_threshold: float = 2.85):
        self.belief_kernel = BayesianBeliefKernel(prior_probabilities)
        self.entropy_gate = EntropyAttestationGate(z_threshold=z_threshold)
        self.action_buffer = ActionBuffer()

    def process_submission(
        self,
        raw_payload: dict,
        likelihoods: Dict[str, float],
        token_logprobs: List[float],
        proposed_actions: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Executes the EpistemicOS control loop with native Saga state management.
        """
        # 1. Process Data Contract & Bayesian Update
        cpr = CanonicalProblemRepresentation(**raw_payload)
        updated_beliefs = self.belief_kernel.update_beliefs(likelihoods)
        map_hypothesis = self.belief_kernel.get_map_estimate()

        # 2. Scope Validation for Proposed Actions
        scope_passed = True
        if proposed_actions:
            for item in proposed_actions:
                action = item.get("action", {})
                if not cpr.scope.validate_action(action):
                    scope_passed = False
                    break
                self.action_buffer.push_action(
                    action=action,
                    rollback_patch=item.get("rollback", {})
                )

        # 3. Evaluate Entropy Gate
        gate_result = self.entropy_gate.evaluate_generation(token_logprobs)

        # If the action violates the permission scope, forcibly fail the gate
        if not scope_passed:
            gate_result["passed"] = False

        # 4. Transaction Lifecycle Control
        if gate_result["passed"]:
            self.action_buffer.commit()
            executed_rollbacks = []
        else:
            executed_rollbacks = self.action_buffer.rollback()

        return {
            "policy_id": cpr.policy_id,
            "serialized_features": cpr.serialize_for_belief_kernel(),
            "posterior_beliefs": updated_beliefs,
            "map_estimate": map_hypothesis,
            "attestation_gate": gate_result,
            "execution_approved": gate_result["passed"],
            "rollbacks_executed": executed_rollbacks
        }
