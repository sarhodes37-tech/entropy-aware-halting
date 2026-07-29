import numpy as np
from typing import List, Dict, Any

class EntropyAttestationGate:
    def __init__(self, z_threshold: float = 2.85):
        """
        Initializes Gate 1 with a critical Z-score threshold (default ~2.85
        corresponding to a p-value cutoff for statistical anomaly).
        """
        self.z_threshold = z_threshold

    def calculate_token_entropy(self, logprobs: List[float]) -> List[float]:
        """Computes Shannon entropy for a list of token log-probabilities."""
        entropies = []
        for lp in logprobs:
            p = np.exp(lp)
            # Prevent log(0) edge cases
            entropy = -p * np.log2(p + 1e-10)
            entropies.append(entropy)
        return entropies

    def evaluate_generation(self, token_logprobs: List[float]) -> Dict[str, Any]:
        """
        Evaluates sequence generation for fluency anchor collapse by measuring
        token-level entropy spikes against a rolling baseline.
        """
        entropies = self.calculate_token_entropy(token_logprobs)

        if not entropies:
            return {"passed": True, "max_z_score": 0.0, "flagged_tokens": 0}

        mean_h = np.mean(entropies)
        std_h = np.std(entropies)

        # Avoid division by zero if all tokens have identical entropy
        if std_h == 0.0:
            std_h = 1e-5

        z_scores = [(h - mean_h) / std_h for h in entropies]
        flagged_count = sum(1 for z in z_scores if z > self.z_threshold)

        passed = flagged_count == 0

        return {
            "passed": passed,
            "max_z_score": float(np.max(z_scores)),
            "flagged_tokens": flagged_count,
            "token_z_scores": z_scores
        }
