from abc import ABC, abstractmethod
from typing import Dict, Any
import numpy as np

class Gate(ABC):
    """Base interface for all EpistemicOS governance gates."""
    @abstractmethod
    def evaluate(self, payload: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        pass

class EntropyGate(Gate):
    def __init__(self, z_threshold: float = 2.85):
        self.z_threshold = z_threshold

    def evaluate(self, payload: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        logprobs = context.get("token_logprobs", [])
        if not logprobs:
            return {"passed": True, "max_z_score": 0.0, "flagged_tokens": 0}

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

        flagged_count = sum(1 for z in z_scores if z > self.z_threshold)
        return {
            "passed": flagged_count == 0,
            "max_z_score": float(np.max(z_scores)) if z_scores else 0.0,
            "flagged_tokens": flagged_count
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
                return {"passed": False, "reason": "Scope validation failed", "action": action}
        return {"passed": True}
