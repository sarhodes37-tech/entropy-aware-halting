"""
Marginal Privacy Utility (MPU) Concept Implementation for Shower Curtain.

Defines decision heuristics for evaluating whether candidate disclosures
are justified by expected task utility improvements relative to incremental
privacy leakage.

Formulation:
MPU = ΔU / (ΔL + ε)
"""

from dataclasses import dataclass
from typing import Dict, Optional, List
from epistemicos.shower_curtain.detector import DetectionResult, SensitivityCategory


@dataclass
class MPUResult:
    delta_u: float  # Estimated utility improvement (0.0 to 1.0)
    delta_l: float  # Estimated incremental privacy leakage (0.0 to 1.0)
    mpu_score: float  # ΔU / (ΔL + ε)
    authorized: bool
    threshold: float
    reason: str


class MarginalPrivacyUtilityEvaluator:
    """
    Evaluates candidate disclosures based on Marginal Privacy Utility.
    """

    SENSITIVITY_WEIGHTS: Dict[SensitivityCategory, float] = {
        SensitivityCategory.CREDENTIAL: 1.0,
        SensitivityCategory.GOV_ID: 0.9,
        SensitivityCategory.FINANCIAL: 0.85,
        SensitivityCategory.EMAIL: 0.5,
        SensitivityCategory.PHONE: 0.6,
        SensitivityCategory.NAME: 0.4,
        SensitivityCategory.ADDRESS: 0.5,
        SensitivityCategory.FILE_PATH: 0.3,
        SensitivityCategory.IP_ADDRESS: 0.3,
        SensitivityCategory.CUSTOM_ENTITY: 0.4,
        SensitivityCategory.UNKNOWN: 0.7,
    }

    def __init__(
        self,
        min_mpu_threshold: float = 0.5,
        epsilon: float = 1e-6
    ):
        self.min_mpu_threshold = min_mpu_threshold
        self.epsilon = epsilon

    def estimate_privacy_leakage(self, detections: List[DetectionResult]) -> float:
        """
        Estimates total privacy leakage ΔL from detected sensitive items.
        Combines sensitivity weights, confidence, and volume.
        """
        if not detections:
            return 0.0

        total_weighted = 0.0
        for d in detections:
            weight = self.SENSITIVITY_WEIGHTS.get(d.category, 0.5)
            total_weighted += weight * d.confidence

        # Normalized non-linear saturation curve: 1 - exp(-total_weighted)
        leakage = 1.0 - math_exp(-total_weighted)
        return min(1.0, max(0.0, leakage))

    def evaluate_disclosure(
        self,
        estimated_utility_gain: float,
        detections: List[DetectionResult],
        custom_threshold: Optional[float] = None
    ) -> MPUResult:
        threshold = custom_threshold if custom_threshold is not None else self.min_mpu_threshold
        delta_u = max(0.0, min(1.0, estimated_utility_gain))
        delta_l = self.estimate_privacy_leakage(detections)

        # MPU = ΔU / (ΔL + ε)
        mpu_score = delta_u / (delta_l + self.epsilon)

        authorized = mpu_score >= threshold
        reason = (
            f"MPU score {mpu_score:.2f} satisfies threshold {threshold:.2f} (ΔU={delta_u:.2f}, ΔL={delta_l:.2f})."
            if authorized
            else f"MPU score {mpu_score:.2f} below required threshold {threshold:.2f} (ΔU={delta_u:.2f}, ΔL={delta_l:.2f})."
        )

        return MPUResult(
            delta_u=round(delta_u, 4),
            delta_l=round(delta_l, 4),
            mpu_score=round(mpu_score, 4),
            authorized=authorized,
            threshold=threshold,
            reason=reason
        )


def math_exp(x: float) -> float:
    import math
    return math.exp(x)
