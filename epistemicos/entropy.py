import numpy as np
from typing import List, Dict, Any

class TokenSurprisalSensor:
    """Canonical statistical sensor for token-level surprisal anomaly detection."""
    def __init__(self, z_threshold: float = 2.85, window_size: int = 10, std_floor: float = 0.05):
        self.z_threshold = z_threshold
        self.window_size = window_size
        self.std_floor = std_floor

    def compute_z_scores(self, logprobs: List[float]) -> List[float]:
        if not logprobs:
            return []

        surprisals = [-lp for lp in logprobs]
        z_scores = []

        for i, h in enumerate(surprisals):
            if i < 2:
                z_scores.append(0.0)
                continue

            start_idx = max(0, i - self.window_size)
            baseline = surprisals[start_idx:i]
            
            mean_h = np.mean(baseline)
            std_h = max(float(np.std(baseline)), self.std_floor)
            
            z_scores.append(float((h - mean_h) / std_h))

        return z_scores

    def evaluate(self, logprobs: List[float]) -> Dict[str, Any]:
        z_scores = self.compute_z_scores(logprobs)
        flagged_count = sum(1 for z in z_scores if z > self.z_threshold)
        max_z = float(np.max(z_scores)) if z_scores else 0.0

        return {
            "passed": flagged_count == 0,
            "max_z_score": max_z,
            "flagged_tokens": flagged_count,
            "token_z_scores": z_scores
        }
