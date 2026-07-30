from abc import ABC, abstractmethod
from typing import Dict, Any
import numpy as np
import time

class Gate(ABC):
    """Base interface for all EpistemicOS governance plugins."""
    @abstractmethod
    def evaluate(self, payload: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Must return a dict containing at least 'passed' (bool) and 'confidence' (float 0.0-1.0)."""
        pass

class EntropyGate(Gate):
    def __init__(self, z_threshold: float = 2.85):
        self.z_threshold = z_threshold

    def evaluate(self, payload: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        logprobs = context.get("token_logprobs", [])
        if not logprobs:
            return {"passed": True, "max_z_score": 0.0, "flagged_tokens": 0, "confidence": 1.0}

        entropies = [-lp for lp in logprobs]
        window_size = 10
        z_scores = []
        for i, h in enumerate(entropies):
            if i < 2:
                z_scores.append(0.0)
                continue
            baseline = entropies[:i] if i < window_size else entropies[i-window_size:i]
            std_h = max(np.std(baseline), 0.05)
            z_scores.append((h - np.mean(baseline)) / std_h)

        max_z = float(np.max(z_scores)) if z_scores else 0.0
        flagged_count = sum(1 for z in z_scores if z > self.z_threshold)

        # Semantic Confidence degrades as Z-score approaches the critical threshold
        confidence = max(0.0, 1.0 - (max_z / self.z_threshold)) if max_z > 0 else 1.0

        return {
            "passed": flagged_count == 0,
            "max_z_score": max_z,
            "flagged_tokens": flagged_count,
            "confidence": round(confidence, 4)
        }

class PermissionGate(Gate):
    def __init__(self, contract_model: Any):
        self.contract_model = contract_model

    def evaluate(self, payload: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        actions = context.get("proposed_actions", [])
        cpr = self.contract_model(**payload)

        for item in actions:
            action = item.get("action", {})
            if not cpr.scope.validate_action(action):
                return {"passed": False, "reason": "Scope validation failed", "action": action, "confidence": 0.0}
        return {"passed": True, "confidence": 1.0}

class CryptoAttestationGate(Gate):
    """Evaluates the cryptographic health and Trust Epoch of the transaction."""
    def __init__(self, required_algorithm: str = "ML-DSA", expiry_year: int = 2030):
        self.required_algorithm = required_algorithm
        self.expiry_year = expiry_year

    def evaluate(self, payload: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        crypto_meta = context.get("cryptography", {})
        algo = crypto_meta.get("algorithm", "RSA-2048")

        # If legacy cryptography is used, confidence plummets and the gate fails
        if algo != self.required_algorithm:
            return {
                "passed": False,
                "reason": f"Deprecated algorithm {algo}. Requires {self.required_algorithm}",
                "confidence": 0.15
            }

        current_year = time.gmtime().tm_year
        time_to_expiry = max(0, self.expiry_year - current_year)
        confidence = min(1.0, time_to_expiry / 5.0) # Confidence decays as the epoch nears its end

        return {"passed": True, "confidence": round(confidence, 4)}
