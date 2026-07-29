import math
from typing import Dict

class BayesianBeliefKernel:
    def __init__(self, prior_probabilities: Dict[str, float]):
        """
        Initializes the belief kernel with prior probabilities for risk hypotheses
        (e.g., {"preferred": 0.5, "standard": 0.3, "substandard": 0.2}).
        """
        self.beliefs = prior_probabilities

    def update_beliefs(self, likelihoods: Dict[str, float]) -> Dict[str, float]:
        """
        Applies Bayes' theorem using likelihoods derived from telemetry data,
        normalizing the resulting posterior distribution.
        """
        unnormalized_posteriors = {}
        for hypothesis, prior in self.beliefs.items():
            likelihood = likelihoods.get(hypothesis, 1.0)
            unnormalized_posteriors[hypothesis] = likelihood * prior

        total_evidence = sum(unnormalized_posteriors.values())
        if total_evidence > 0:
            self.beliefs = {
                h: v / total_evidence for h, v in unnormalized_posteriors.items()
            }

        return self.beliefs

    def get_map_estimate(self) -> str:
        """Returns the Maximum A Posteriori (MAP) risk hypothesis."""
        return max(self.beliefs, key=self.beliefs.get)
