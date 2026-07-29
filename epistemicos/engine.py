from typing import Dict, Any, List
from epistemicos.cpr import CanonicalProblemRepresentation
from epistemicos.beliefs import BayesianBeliefKernel
from epistemicos.entropy import EntropyAttestationGate

class EpistemicEngine:
    def __init__(self, prior_probabilities: Dict[str, float], z_threshold: float = 2.85):
        self.belief_kernel = BayesianBeliefKernel(prior_probabilities)
        self.entropy_gate = EntropyAttestationGate(z_threshold=z_threshold)

    def process_submission(
        self,
        raw_payload: dict,
        likelihoods: Dict[str, float],
        token_logprobs: List[float]
    ) -> Dict[str, Any]:
        """
        Executes the full EpistemicOS control loop:
        1. Validates and normalizes payload via CPR.
        2. Updates risk beliefs via Bayesian kernel.
        3. Attests generation integrity via Gate 1 entropy check.
        """
        # 1. Canonical Problem Representation Validation
        cpr = CanonicalProblemRepresentation(**raw_payload)

        # 2. Bayesian Belief Update
        updated_beliefs = self.belief_kernel.update_beliefs(likelihoods)
        map_hypothesis = self.belief_kernel.get_map_estimate()

        # 3. Entropy Attestation Gate
        gate_result = self.entropy_gate.evaluate_generation(token_logprobs)

        return {
            "policy_id": cpr.policy_id,
            "serialized_features": cpr.serialize_for_belief_kernel(),
            "posterior_beliefs": updated_beliefs,
            "map_estimate": map_hypothesis,
            "attestation_gate": gate_result,
            "execution_approved": gate_result["passed"]
        }
