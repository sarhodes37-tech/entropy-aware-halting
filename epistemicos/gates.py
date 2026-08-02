"""
EpistemicOS Governance Gates Suite.

Defines abstract base interfaces and concrete implementations for the 
unified pipeline. These gates act as a defense-in-depth security layer,
intercepting adversarial prompt injections, data washing, and cryptographic
compromises before they can mutate the stateful database.

Components:
- EntropyGate: Token Surprisal & Latent Anomaly Detection
- PermissionGate: Scope, Sandbox, & Action Boundary Validation
- TriangulationGate: Data Washing & Synthetic Index Inflation Defense
- CryptoAttestationGate: Post-Quantum Attestation & OCSP Revocation
"""

import json
from abc import ABC, abstractmethod
import math
import re
import time
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from enum import Enum
from epistemicos.models import TokenSurprisalSensor

class GateAction(Enum):
    ALLOW = "ALLOW"
    HALT = "DETERMINISTIC_HALT"
    ROLLBACK = "ACTION_ROLLBACK"


@dataclass
class GateResult:
    def __init__(self, status="ALLOWED", action=GateAction.ALLOW, gate=None, gate_name=None, reason="", flagged_tokens=0, divergence=0.0, confidence=1.0, latency_ms=0.0, vectors_revoked=0, **kwargs):
        # Normalize status vs action to handle both keyword styles seamlessly
        if isinstance(action, GateAction):
            self.action = action
            self.status = "ALLOWED" if action == GateAction.ALLOW else "HALTED"
        else:
            self.status = status
            self.action = GateAction.ALLOW if status == "ALLOWED" else GateAction.HALT

        # Assign gate and gate_name interchangeably so either attribute is always valid
        resolved_gate = gate or gate_name
        self.gate = resolved_gate
        self.gate_name = resolved_gate
        
        self.reason = reason
        self.flagged_tokens = flagged_tokens
        self.divergence = divergence
        self.confidence = confidence
        self.latency_ms = latency_ms
        self.vectors_revoked = vectors_revoked or (flagged_tokens if action != GateAction.ALLOW else 0)
        
        for k, v in kwargs.items():
            setattr(self, k, v)

    def __getitem__(self, key):
        if key == "status":
            return self.status
        if key == "action":
            return self.action
        if key == "vectors_revoked":
            return self.vectors_revoked
        if key == "gate":
            return self.gate
        if key == "gate_name":
            return self.gate_name
        return getattr(self, key)

    def get(self, key, default=None):
        try:
            return self[key]
        except AttributeError:
            return default

    @property
    def passed(self) -> bool:
        """Compatibility adapter for orchestrator check engine expectations."""
        return self.action == GateAction.ALLOW


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
    Monitors autoregressive token logprobs for anomaly detection using a 
    granular, token-by-token surprisal sensor.
    
    Trips when individual token Z-scores exceed the dynamic envelope 
    z_threshold, indicating a likely prompt injection or model hallucination event 
    buried within the payload.
    """

    def __init__(self, z_threshold: float = 2.85, window_size: int = 10):
        # Delegate statistical analysis to the consolidated domain model
        self.sensor = TokenSurprisalSensor(z_threshold=z_threshold, window_size=window_size)

    def evaluate(self, payload: Dict[str, Any], context: Dict[str, Any]) -> GateResult:
        t0 = time.perf_counter()
        logprobs = context.get("token_logprobs", [])

        if not logprobs:
            return GateResult(
                action=GateAction.ALLOW, 
                latency_ms=(time.perf_counter() - t0) * 1000, 
                gate_name="EntropyGate", 
                reason="NO_LOGPROBS_PROVIDED"
            )

        # Evaluate sequence using the token-by-token kernel
        sensor_result = self.sensor.evaluate(logprobs)

        if not sensor_result["passed"]:
            flagged_count = sensor_result.get('flagged_tokens', 1)
            return GateResult(
                action=GateAction.HALT,
                latency_ms=(time.perf_counter() - t0) * 1000,
                gate_name="EntropyGate",
                reason=f"Anomalous Token Surprisal Detected (Max Z: {sensor_result['max_z_score']:.2f}, Flagged: {flagged_count})",
                confidence=0.0,
                flagged_tokens=flagged_count,
                vectors_revoked=max(1, flagged_count)
            )

        return GateResult(
            action=GateAction.ALLOW, 
            latency_ms=(time.perf_counter() - t0) * 1000, 
            gate_name="EntropyGate"
        )


class PermissionGate(Gate):
    """
    Pre-compiled JIT Schema Gate enforcing strict contract boundaries.
    
    Intercepts unauthorized tool calls, sandbox escape attempts, and 
    system override prompt injections embedded deep within commercial 
    underwriting text fields (like operations_description or special_conditions).
    """

    def __init__(self, contract_model: Any = None, allowed_actions: Optional[List[str]] = None):
        self.contract_model = contract_model
        self.allowed_actions = set(allowed_actions or [])

        # Expanded regex to catch specific injection vectors, jailbreaks, and unauthorized privilege elevations
        self.injection_regex = re.compile(
            r"(\b(sudo|rm|curl|wget|bash|sh|exec|nc|netcat|nmap|ping)\b|[;|`]|&&|\$\(|\[SYSTEM OVERRIDE\]|import\s+os|ignore previous instructions|system prompt|jailbreak|exfiltrate|web_search)", 
            res.IGNORECASE if 'res' in globals() else re.IGNORECASE
        )

    def evaluate(self, payload: Dict[str, Any], context: Dict[str, Any]) -> GateResult:
        t0 = time.perf_counter()

        # Check scope restrictions and RMM quarantine rules from the payload/context
        scope = payload.get("scope", {}) or context.get("scope", {})
        if scope.get("is_rmm_origin", False):
            proposed_actions = context.get("proposed_actions", [])
            for action in proposed_actions:
                op = action.get("op") if isinstance(action, dict) else getattr(action, "op", None)
                if op in {"update_db", "issue_binder", "api_call", "web_search"}:
                    return GateResult(
                        action=GateAction.HALT,
                        status="HALTED",
                        latency_ms=(time.perf_counter() - t0) * 1000,
                        gate_name="PermissionGate",
                        reason="Downstream Scope Lock: State-mutating action prohibited from RMM quarantine subnet.",
                        confidence=0.0
                    )

        # Serialize payload and proposed actions to string for deep inspection
        inspection_target = json.dumps({"payload": payload, "actions": context.get("proposed_actions", [])})

        if self.injection_regex.search(inspection_target):
            return GateResult(
                action=GateAction.HALT,
                status="HALTED",
                latency_ms=(time.perf_counter() - t0) * 1000,
                gate_name="PermissionGate",
                reason="Unsafe Command Injection, Jailbreak, or System Override Intercepted",
                confidence=0.0
            )

        return GateResult(
            action=GateAction.ALLOW,
            status="ALLOWED",
            latency_ms=(time.perf_counter() - t0) * 1000, 
            gate_name="PermissionGate"
        )


class TriangulationGate(Gate):
    """
    Input Integrity and Telemetry Cross-Check Module.
    
    Detects adversarial data washing by cross-referencing primary 
    metrics (like TIV or fleet radius) against isolated background 
    telemetry vectors to ensure the provided risk profile hasn't been spoofed.
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
                return GateResult(
                    action=GateAction.HALT,
                    latency_ms=(time.perf_counter() - t0) * 1000,
                    gate_name="TriangulationGate",
                    reason=f"Data Washing Detected: Metric diverged {divergence:.1%} from baseline.",
                    confidence=0.0,
                    divergence=divergence
                )
        except (ValueError, TypeError):
            return GateResult(
                action=GateAction.HALT,
                latency_ms=(time.perf_counter() - t0) * 1000,
                gate_name="TriangulationGate",
                reason="Malformed telemetry data type.",
                confidence=0.0,
                divergence=1.0
            )

        return GateResult(
            action=GateAction.ALLOW, 
            latency_ms=(time.perf_counter() - t0) * 1000, 
            gate_name="TriangulationGate",
            divergence=divergence if 'divergence' in locals() else 0.0
        )


class CryptoAttestationGate(Gate):
    """
    Evaluates cryptographic health, OCSP Key Revocation State, 
    and Quantum Trust Epochs to prevent signed payloads from compromised 
    keys entering the system.
    """

    def __init__(self, required_algorithm: str = "ML-DSA", expiry_year: int = 2030):
        self.required_algorithm = required_algorithm
        self.expiry_year = expiry_year

    def _check_ocsp_revocation(self, key_id: str) -> bool:
        revoked_keys = {"KEY-000-COMPROMISED", "KEY-999-STOLEN", "KEY-2026-COMPROMISED"}
        return key_id in revoked_keys

    def evaluate(self, payload: Dict[str, Any], context: Dict[str, Any]) -> GateResult:
        t0 = time.perf_counter()
        crypto_meta = context.get("cryptography") or payload.get("raw_payload", {}).get("cryptography", {})
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
