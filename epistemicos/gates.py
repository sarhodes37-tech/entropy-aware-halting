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
    """Evaluates the cryptographic health, Revocation State, and Trust Epoch of the transaction."""
    def __init__(self, required_algorithm: str = "ML-DSA", expiry_year: int = 2030, ocsp_endpoint: str = "https://ca.epistemicos.internal/ocsp"):
        self.required_algorithm = required_algorithm
        self.expiry_year = expiry_year
        self.ocsp_endpoint = ocsp_endpoint

    def _check_ocsp_revocation(self, key_id: str) -> bool:
        """
        Simulates a low-latency UDP/HTTP ping to an Online Certificate Status Protocol responder.
        Returns True if the key is revoked/compromised.
        """
        # Mocking a known compromised key
        revoked_keys = ["KEY-000-COMPROMISED", "KEY-999-STOLEN"]
        return key_id in revoked_keys

    def evaluate(self, payload: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        crypto_meta = context.get("cryptography", {})
        algo = crypto_meta.get("algorithm", "RSA-2048")
        key_id = crypto_meta.get("key_id", "UNKNOWN_KEY")

        # 1. Stateful Revocation Check (The Hot Path)
        is_revoked = self._check_ocsp_revocation(key_id)
        if is_revoked:
            return {
                "passed": False,
                "reason": f"CRITICAL: Key {key_id} is flagged as REVOKED by OCSP.",
                "confidence": 0.0
            }

        # 2. Cryptographic Epoch Check
        if algo != self.required_algorithm:
            return {
                "passed": False,
                "reason": f"Deprecated algorithm {algo}. Requires {self.required_algorithm}",
                "confidence": 0.15
            }

        current_year = time.gmtime().tm_year
        time_to_expiry = max(0, self.expiry_year - current_year)
        confidence = min(1.0, time_to_expiry / 5.0)

        return {"passed": True, "confidence": round(confidence, 4)}

class TriangulationGate(Gate):
    """Guards against data washing and synthetic index inflation by cross-referencing metrics against secondary feeds."""
    def __init__(self, max_divergence_threshold: float = 0.15):
        self.max_divergence_threshold = max_divergence_threshold

    def evaluate(self, payload: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        primary_metric = payload.get("primary_metric")
        secondary_feeds = context.get("heterogeneous_telemetry", [])

        if primary_metric is None:
            # If the payload lacks a primary metric to triangulate, pass but log unverified
            return {"passed": True, "confidence": 1.0}

        if not secondary_feeds:
            return {
                "passed": True,
                "confidence": 0.50,
                "reason": "UNVERIFIED_SINGLE_SOURCE"
            }

        # Calculate absolute divergence (mean variance between primary and secondary feeds)
        variances = [abs(primary_metric - feed_val) / max(primary_metric, 1e-5) for feed_val in secondary_feeds]
        mean_divergence = sum(variances) / len(variances)

        if mean_divergence > self.max_divergence_threshold:
            return {
                "passed": False,
                "confidence": 0.0,
                "reason": f"Divergence failure. Metric {primary_metric} washed/inflated against secondary telemetry."
            }

        confidence = round(1.0 - mean_divergence, 4)
        return {"passed": True, "confidence": confidence}
