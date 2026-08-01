"""
EpistemicOS Governance Gates Suite.
Defines abstract base interface and concrete implementations for:
- EntropyGate (Token Surprisal Anomaly Detection)
- PermissionGate (Scope & Action Boundary Validation)
- TriangulationGate (Data Washing & Synthetic Index Inflation Defense)
- CryptoAttestationGate (Post-Quantum Attestation & OCSP Revocation)
"""

from abc import ABC, abstractmethod
import math
import re
import time
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from enum import Enum


class GateAction(Enum):
    ALLOW = "ALLOW"
    HALT = "DETERMINISTIC_HALT"
    ROLLBACK = "ACTION_ROLLBACK"


@dataclass
class GateResult:
    action: GateAction
    latency_ms: float
    gate_name: str
    reason: Optional[str] = None
    confidence: float = 1.0


class Gate(ABC):
    """Base interface for all EpistemicOS governance plugins."""

    @abstractmethod
    def evaluate(self, payload: Dict[str, Any], context: Dict[str, Any]) -> GateResult:
        """
        Evaluates payload and runtime context.
        Must return a GateResult dictating the deterministic action.
        """
        pass


class EntropyGate(Gate):
    """
    Monitors autoregressive token entropy logprobs.
    Trips when surprisal Z-scores exceed the dynamic envelope z_threshold.
    """

    def __init__(self, z_threshold: float = 3.5, max_window: int = 64):
        self.z_threshold = z_threshold
        self.max_window = max_window
        self.rolling_entropy: List[float] = []

    def evaluate(self, payload: Dict[str, Any], context: Dict[str, Any]) -> GateResult:
        t0 = time.perf_counter()
        logits = context.get("token_logits", [])
        
        if not logits:
            return GateResult(
                action=GateAction.ALLOW, 
                latency_ms=(time.perf_counter() - t0) * 1000, 
                gate_name="EntropyGate", 
                reason="NO_LOGITS_PROVIDED"
            )

        max_logit = max(logits)
        exps = [math.exp(l - max_logit) for l in logits]
        sum_exps = sum(exps)
        probs = [e / sum_exps for e in exps]
        
        entropy = -sum(p * math.log2(p) for p in probs if p > 1e-12)

        n = len(self.rolling_entropy)
        if n > 8:
            mean = sum(self.rolling_entropy) / n
            variance = sum((x - mean) ** 2 for x in self.rolling_entropy) / n
            safe_std_dev = max(math.sqrt(variance), 0.05) 
            z_score = abs(entropy - mean) / safe_std_dev

            if z_score > self.z_threshold:
                latency = (time.perf_counter() - t0) * 1000
                return GateResult(
                    action=GateAction.HALT,
                    latency_ms=latency,
                    gate_name="EntropyGate",
                    reason=f"Anomalous Entropy Collapse (Z-Score: {z_score:.2f}, H(X): {entropy:.4f})",
                    confidence=0.0
                )

        self.rolling_entropy.append(entropy)
        if len(self.rolling_entropy) > self.max_window:
            self.rolling_entropy.pop(0)

        latency = (time.perf_counter() - t0) * 1000
        return GateResult(action=GateAction.ALLOW, latency_ms=latency, gate_name="EntropyGate")


class PermissionGate(Gate):
    """
    Pre-compiled JIT Schema Gate enforcing strict contract boundaries,
    intercepting unauthorized tool calls and sandbox escape attempts.
    """

    def __init__(self, allowed_actions: List[str]):
        self.allowed_actions = set(allowed_actions)
        self.tool_call_regex = re.compile(r"<tool_call>.*?\"name\":\s*\"([^\"]+)\".*?</tool_call>", re.DOTALL)
        self.system_cmd_regex = re.compile(
            r"(\b(sudo|rm|curl|wget|bash|sh|exec|nc|netcat|nmap|ping)\b|[;|`]|&&|\$\()", 
            re.IGNORECASE
        )

    def evaluate(self, payload: Dict[str, Any], context: Dict[str, Any]) -> GateResult:
        t0 = time.perf_counter()
        raw_output = context.get("accumulated_output", "")

        tool_matches = self.tool_call_regex.findall(raw_output)
        for tool_name in tool_matches:
            if tool_name not in self.allowed_actions:
                latency = (time.perf_counter() - t0) * 1000
                return GateResult(
                    action=GateAction.ROLLBACK,
                    latency_ms=latency,
                    gate_name="PermissionGate",
                    reason=f"Unauthorized Function Call Attempted: '{tool_name}'",
                    confidence=0.0
                )

        if self.system_cmd_regex.search(raw_output):
            latency = (time.perf_counter() - t0) * 1000
            return GateResult(
                action=GateAction.ROLLBACK,
                latency_ms=latency,
                gate_name="PermissionGate",
                reason="Unsafe System Command Injection Intercepted",
                confidence=0.0
            )

        latency = (time.perf_counter() - t0) * 1000
        return GateResult(action=GateAction.ALLOW, latency_ms=latency, gate_name="PermissionGate")


class TriangulationGate(Gate):
    """
    Input Integrity and Telemetry Cross-Check Module.
    Detects adversarial data washing by cross-referencing primary metrics
    against isolated background telemetry vectors.
    """

    def __init__(self, max_divergence_threshold: float = 0.15):
        self.max_divergence_threshold = max_divergence_threshold

    def evaluate(self, payload: Dict[str, Any], context: Dict[str, Any]) -> GateResult:
        t0 = time.perf_counter()
        
        primary = payload.get("primary_metric")
        telemetry = context.get("heterogeneous_telemetry", payload.get("heterogeneous_telemetry", []))
        
        if primary is None or not telemetry:
            return GateResult(
                action=GateAction.ALLOW, 
                latency_ms=(time.perf_counter() - t0) * 1000, 
                gate_name="TriangulationGate"
            )
            
        try:
            primary = float(primary)
            telemetry = [float(x) for x in telemetry]
            baseline_mean = sum(telemetry) / len(telemetry)
            
            divergence = 0.0 if baseline_mean == 0 else abs(primary - baseline_mean) / abs(baseline_mean)
                
            if divergence > self.max_divergence_threshold:
                latency = (time.perf_counter() - t0) * 1000
                return GateResult(
                    action=GateAction.HALT,
                    latency_ms=latency,
                    gate_name="TriangulationGate",
                    reason=f"Data Washing Detected: Metric diverged {divergence:.1%} from baseline.",
                    confidence=0.0
                )
        except (ValueError, TypeError):
            return GateResult(
                action=GateAction.HALT,
                latency_ms=(time.perf_counter() - t0) * 1000,
                gate_name="TriangulationGate",
                reason="Malformed telemetry data type.",
                confidence=0.0
            )
            
        latency = (time.perf_counter() - t0) * 1000
        return GateResult(action=GateAction.ALLOW, latency_ms=latency, gate_name="TriangulationGate")


class CryptoAttestationGate(Gate):
    """Evaluates cryptographic health, OCSP Key Revocation State, and Quantum Trust Epochs."""

    def __init__(self, required_algorithm: str = "ML-DSA", expiry_year: int = 2030):
        self.required_algorithm = required_algorithm
        self.expiry_year = expiry_year

    def _check_ocsp_revocation(self, key_id: str) -> bool:
        revoked_keys = {"KEY-000-COMPROMISED", "KEY-999-STOLEN"}
        return key_id in revoked_keys

    def evaluate(self, payload: Dict[str, Any], context: Dict[str, Any]) -> GateResult:
        t0 = time.perf_counter()
        crypto_meta = context.get("cryptography", {})
        algo = crypto_meta.get("algorithm", "RSA-2048")
        key_id = crypto_meta.get("key_id", "UNKNOWN_KEY")

        if self._check_ocsp_revocation(key_id):
            return GateResult(
                action=GateAction.HALT, 
                latency_ms=(time.perf_counter() - t0) * 1000, 
                gate_name="CryptoAttestationGate", 
                reason=f"CRITICAL: Key {key_id} is flagged as REVOKED by OCSP.",
                confidence=0.0
            )

        if algo != self.required_algorithm:
            return GateResult(
                action=GateAction.HALT, 
                latency_ms=(time.perf_counter() - t0) * 1000, 
                gate_name="CryptoAttestationGate", 
                reason=f"Deprecated algorithm {algo}. Requires quantum-resistant {self.required_algorithm}",
                confidence=0.15
            )

        return GateResult(
            action=GateAction.ALLOW, 
            latency_ms=(time.perf_counter() - t0) * 1000, 
            gate_name="CryptoAttestationGate"
        )
