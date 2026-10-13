"""
Stage E: Egress Gate for Shower Curtain.

Evaluates final serialized outbound payloads against privacy policy before
transmission to external AI providers. Defaults to fail-closed behavior.
"""

import time
import json
from typing import Dict, Any, List, Optional
from epistemicos.gates import Gate, GateAction, GateResult
from epistemicos.shower_curtain.detector import SensitiveDataDetector, SensitivityCategory
from epistemicos.shower_curtain.policy import PrivacyPolicy, PrivacyTreatment


class ShowerCurtainGate(Gate):
    """
    Egress Policy Gate evaluating final serialized payloads against privacy policy.
    Enforces strict fail-closed behavior.
    """

    def __init__(
        self,
        detector: Optional[SensitiveDataDetector] = None,
        policy: Optional[PrivacyPolicy] = None
    ):
        self.detector = detector or SensitiveDataDetector()
        self.policy = policy or PrivacyPolicy()

    def evaluate(self, payload: Dict[str, Any], context: Dict[str, Any]) -> GateResult:
        t0 = time.perf_counter()

        # Check explicit exception authorization
        if context.get("shower_curtain_exception_authorized") is True:
            return GateResult(
                action=GateAction.ALLOW,
                status="ALLOWED",
                latency_ms=(time.perf_counter() - t0) * 1000,
                gate_name="ShowerCurtainGate",
                reason="EXPLICIT_PRIVACY_EXCEPTION_AUTHORIZED"
            )

        # Inspect actual serialized string payload or prompt
        if isinstance(payload, dict):
            text_content = json.dumps(payload, sort_keys=True)
        elif isinstance(payload, str):
            text_content = payload
        else:
            text_content = str(payload)

        if not text_content or text_content == "{}":
            return GateResult(
                action=GateAction.ALLOW,
                status="ALLOWED",
                latency_ms=(time.perf_counter() - t0) * 1000,
                gate_name="ShowerCurtainGate",
                reason="NO_PAYLOAD_TEXT_TO_INSPECT"
            )

        # Detect remaining unredacted sensitive items
        detections = self.detector.detect(text_content)
        destination = context.get("destination_provider", "external_model")

        unauthorized_leaks = []
        for det in detections:
            decision = self.policy.evaluate(det, destination=destination)
            # If policy requires REDACT or BLOCK but item is still present in raw form
            if decision.treatment in (PrivacyTreatment.BLOCK, PrivacyTreatment.REDACT):
                unauthorized_leaks.append(det)

        if unauthorized_leaks:
            cat_names = sorted(set(d.category.value for d in unauthorized_leaks))
            return GateResult(
                action=GateAction.HALT,
                status="HALTED",
                latency_ms=(time.perf_counter() - t0) * 1000,
                gate_name="ShowerCurtainGate",
                reason=f"Egress Gate Denied: Unsanitized sensitive data detected in final payload ({', '.join(cat_names)}).",
                confidence=0.0,
                vectors_revoked=1
            )

        return GateResult(
            action=GateAction.ALLOW,
            status="ALLOWED",
            latency_ms=(time.perf_counter() - t0) * 1000,
            gate_name="ShowerCurtainGate",
            reason="Payload sanitized and egress policy satisfied."
        )
