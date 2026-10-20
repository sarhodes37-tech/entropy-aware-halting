"""
Stage E: Egress Gate for Shower Curtain.

Evaluates final serialized outbound payloads against privacy policy before
transmission to external AI providers. Defaults to fail-closed behavior.
"""

import time
import json
import hmac
from typing import Dict, Any, List, Optional, Set
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
        policy: Optional[PrivacyPolicy] = None,
        trusted_exception_token: Optional[str] = None
    ):
        self.detector = detector or SensitiveDataDetector()
        self.policy = policy or PrivacyPolicy()
        self.trusted_exception_token = trusted_exception_token

    def evaluate(
        self,
        payload: Dict[str, Any],
        context: Dict[str, Any]
    ) -> GateResult:
        t0 = time.perf_counter()

        # Unauthenticated context checks must NOT grant exception bypass.
        # Exception authorization requires verifying trusted_exception_token in constant time to prevent timing attacks.
        provided_token = context.get("shower_curtain_exception_token")
        if (
            self.trusted_exception_token
            and isinstance(provided_token, str)
            and isinstance(self.trusted_exception_token, str)
            and hmac.compare_digest(provided_token, self.trusted_exception_token)
        ):
            if isinstance(payload, dict):
                text_check = json.dumps(payload, sort_keys=True)
            else:
                text_check = str(payload)
            dets = self.detector.detect(text_check)
            if any(d.category == SensitivityCategory.CREDENTIAL for d in dets):
                return GateResult(
                    action=GateAction.HALT,
                    status="HALTED",
                    latency_ms=(time.perf_counter() - t0) * 1000,
                    gate_name="ShowerCurtainGate",
                    reason="Egress Gate Denied: Credentials cannot bypass mandatory privacy protection even with exception token.",
                    confidence=0.0,
                    vectors_revoked=1
                )
            return GateResult(
                action=GateAction.ALLOW,
                status="ALLOWED",
                latency_ms=(time.perf_counter() - t0) * 1000,
                gate_name="ShowerCurtainGate",
                reason="EXPLICIT_PRIVACY_EXCEPTION_AUTHORIZED_VIA_TRUSTED_TOKEN"
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
        placeholders = context.get("registered_placeholders", set())

        unauthorized_leaks = []
        for det in detections:
            # If detected value is an authorized registered placeholder, skip leak flagging
            if det.value in placeholders:
                continue

            decision = self.policy.evaluate(det, destination=destination)
            # Any un-sanitized sensitive value requiring treatment that is still present raw is an egress leak
            if decision.treatment != PrivacyTreatment.PASS:
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
