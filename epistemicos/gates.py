"""
EpistemicOS Governance Gates Suite.
Defines abstract base interface and concrete implementations for:
- EntropyGate (Token Surprisal Anomaly Detection)
- PermissionGate (Scope & Action Boundary Validation)
- CryptoAttestationGate (Post-Quantum Attestation & OCSP Revocation)
- TriangulationGate (Data Washing & Synthetic Index Inflation Defense)
"""

from abc import ABC, abstractmethod
import time
from typing import Dict, Any, List, Optional
import numpy as np


class Gate(ABC):
    """Base interface for all EpistemicOS governance plugins."""

    @abstractmethod
    def evaluate(self, payload: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates payload and runtime context.
        Must return a dict containing at least 'passed' (bool) and 'confidence' (float 0.0-1.0).
        """
        pass


class EntropyGate(Gate):
    """
    Monitors autoregressive token entropy logprobs.
    Trips when surprisal Z-scores exceed the dynamic envelope z_threshold.
    """

    def __init__(self, z_threshold: float = 2.85, window_size: int = 10):
        self.z_threshold = z_threshold
        self.window_size = window_size

    def evaluate(self, payload: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        logprobs = context.get("token_logprobs", [])
        if not logprobs:
            return {
                "passed": True,
                "max_z_score": 0.0,
                "flagged_tokens": 0,
                "confidence": 1.0,
                "reason": "NO_TOKENS_PROVIDED"
            }

        entropies = [-lp for lp in logprobs]
        z_scores: List[float] = []

        for i, h in enumerate(entropies):
            if i < 2:
                z_scores.append(0.0)
                continue
            baseline = entropies[:i] if i < self.window_size else entropies[i - self.window_size:i]
            std_h = max(float(np.std(baseline)), 0.05)
            z_scores.append((h - float(np.mean(baseline))) / std_h)

        max_z = float(np.max(z_scores)) if z_scores else 0.0
        flagged_count = sum(1 for z in z_scores if z > self.z_threshold)

        # Semantic confidence degrades as Z-score approaches critical threshold
        confidence = max(0.0, 1.0 - (max_z / self.z_threshold)) if max_z > 0 else 1.0

        return {
            "passed": flagged_count == 0,
            "max_z_score": round(max_z, 4),
            "flagged_tokens": flagged_count,
            "confidence": round(confidence, 4),
            "reason": "CLEAN_ENTROPY_TRAJECTORY" if flagged_count == 0 else "ENTROPY_SPIKE_DETECTED"
        }


class PermissionGate(Gate):
    """
    Evaluates proposed actions against CanonicalProblemRepresentation (CPR)
    scope boundaries and server-side stateful retry limits.
    """

    def __init__(self, contract_model: Any):
        self.contract_model = contract_model

    def evaluate(self, payload: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        actions = context.get("proposed_actions", [])

        try:
            if isinstance(payload, self.contract_model):
                cpr = payload
            else:
                cpr = self.contract_model(**payload)
        except Exception as e:
            return {
                "passed": False,
                "reason": f"Contract Schema Failure: {e}",
                "confidence": 0.0
            }

        # Sync authoritative server-side attempt count if present in execution context
        if "server_attempt_count" in context:
            cpr.scope.attempt_count = context["server_attempt_count"]

        for item in actions:
            action = item.get("action", {})
            if not cpr.scope.validate_action(action):
                return {
                    "passed": False,
                    "reason": "Permission scope validation failed",
                    "action": action,
                    "confidence": 0.0
                }

        return {
            "passed": True,
            "confidence": 1.0,
            "reason": "SCOPE_VALIDATED"
        }


class CryptoAttestationGate(Gate):
    """Evaluates cryptographic health, OCSP Key Revocation State, and Quantum Trust Epochs."""

    def __init__(
        self,
        required_algorithm: str = "ML-DSA",
        expiry_year: int = 2030,
        ocsp_endpoint: str = "https://ca.epistemicos.internal/ocsp"
    ):
        self.required_algorithm = required_algorithm
        self.expiry_year = expiry_year
        self.ocsp_endpoint = ocsp_endpoint

    def _check_ocsp_revocation(self, key_id: str) -> bool:
        """Simulates low-latency OCSP responder lookup for compromised/revoked keys."""
        revoked_keys = {"KEY-000-COMPROMISED", "KEY-999-STOLEN"}
        return key_id in revoked_keys

    def evaluate(self, payload: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        crypto_meta = context.get("cryptography", {})
        algo = crypto_meta.get("algorithm", "RSA-2048")
        key_id = crypto_meta.get("key_id", "UNKNOWN_KEY")

        # 1. Hot-path OCSP Revocation Check
        if self._check_ocsp_revocation(key_id):
            return {
                "passed": False,
                "reason": f"CRITICAL: Key {key_id} is flagged as REVOKED by OCSP.",
                "confidence": 0.0
            }

        # 2. Cryptographic Epoch Check (Enforce Post-Quantum Algorithm Standard)
        if algo != self.required_algorithm:
            return {
                "passed": False,
                "reason": f"Deprecated algorithm {algo}. Requires quantum-resistant {self.required_algorithm}",
                "confidence": 0.15
            }

        current_year = time.gmtime().tm_year
        time_to_expiry = max(0, self.expiry_year - current_year)
        confidence = min(1.0, time_to_expiry / 5.0)

        return {
            "passed": True,
            "confidence": round(confidence, 4),
            "reason": "ATTESTATION_VALIDATED"
        }


class TriangulationGate(Gate):
    """Guards against Data Washing by cross-referencing metrics against secondary telemetry feeds."""

    def __init__(self, max_divergence_threshold: float = 0.15):
        self.max_divergence_threshold = max_divergence_threshold

    def evaluate(self, payload: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        primary_metric = payload.get("primary_metric")

        # Check context first; fall back to raw_payload
        secondary_feeds = context.get("heterogeneous_telemetry")
        if secondary_feeds is None:
            secondary_feeds = payload.get("heterogeneous_telemetry", [])

        if primary_metric is None:
            return {
                "passed": True,
                "confidence": 1.0,
                "reason": "NO_PRIMARY_METRIC_TO_TRIANGULATE"
            }

        if not secondary_feeds:
            return {
                "passed": True,
                "confidence": 0.50,
                "reason": "UNVERIFIED_SINGLE_SOURCE"
            }

        # Compute mean absolute normalized divergence across secondary telemetry
        variances = [
            abs(primary_metric - feed_val) / max(abs(primary_metric), 1e-5)
            for feed_val in secondary_feeds
        ]
        mean_divergence = sum(variances) / len(variances)

        if mean_divergence > self.max_divergence_threshold:
            return {
                "passed": False,
                "divergence": round(mean_divergence, 4),
                "threshold": self.max_divergence_threshold,
                "confidence": 0.0,
                "reason": f"DATA_WASHING_DIVERGENCE_EXCEEDED: Metric {primary_metric} failed triangulation against secondary telemetry."
            }

        confidence = round(1.0 - mean_divergence, 4)
        return {
            "passed": True,
            "divergence": round(mean_divergence, 4),
            "confidence": max(0.0, min(1.0, confidence)),
            "reason": "CLEAN_TRIANGULATION"
        }
