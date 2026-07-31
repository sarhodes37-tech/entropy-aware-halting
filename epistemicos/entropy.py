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
            # Calculate token entropy (surprise) simply as -logprob to ensure extreme noise registers appropriately
            entropy = -lp
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

        # Evaluate token-level entropy spikes against a rolling baseline
        window_size = 10
        z_scores = []
        for i, h in enumerate(entropies):
            if i < window_size:
                if i < 2:
                    z_scores.append(0.0)
                else:
                    baseline = entropies[:i]
                    mean_h = np.mean(baseline)
                    std_h = np.std(baseline)
                    # Ensure standard deviation doesn't collapse to near-zero for uniform distributions
                    # which would artificially inflate Z-scores of normal text.
                    if std_h < 0.05:
                        std_h = 0.05
                    z_scores.append((h - mean_h) / std_h)
            else:
                baseline = entropies[i-window_size:i]
                mean_h = np.mean(baseline)
                std_h = np.std(baseline)
                if std_h < 0.05:
                    std_h = 0.05
                z_scores.append((h - mean_h) / std_h)

        flagged_count = sum(1 for z in z_scores if z > self.z_threshold)

        passed = flagged_count == 0

        return {
            "passed": passed,
            "max_z_score": float(np.max(z_scores)),
            "flagged_tokens": flagged_count,
            "token_z_scores": z_scores
        }
