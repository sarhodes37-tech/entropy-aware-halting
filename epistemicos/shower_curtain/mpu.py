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
        import math
        if isinstance(min_mpu_threshold, bool) or not isinstance(min_mpu_threshold, (int, float)):
            raise TypeError(f"min_mpu_threshold must be numeric, got {type(min_mpu_threshold).__name__}")
        if not math.isfinite(min_mpu_threshold) or min_mpu_threshold < 0.0:
            raise ValueError(f"min_mpu_threshold must be a finite non-negative number, got {min_mpu_threshold}")

        if isinstance(epsilon, bool) or not isinstance(epsilon, (int, float)):
            raise TypeError(f"epsilon must be numeric, got {type(epsilon).__name__}")
        if not math.isfinite(epsilon) or epsilon <= 0.0:
            raise ValueError(f"epsilon must be a finite positive number, got {epsilon}")

        self.min_mpu_threshold = float(min_mpu_threshold)
        self.epsilon = float(epsilon)

    def estimate_privacy_leakage(self, detections: List[DetectionResult]) -> float:
        """
        Estimates total privacy leakage ΔL from detected sensitive items.
        Combines sensitivity weights, confidence, and volume.
        Fails closed on non-finite or invalid confidence scores.
        """
        import math
        if not detections:
            return 0.0

        total_weighted = 0.0
        for d in detections:
            weight = self.SENSITIVITY_WEIGHTS.get(d.category, 0.5)
            conf = getattr(d, "confidence", 1.0)
            if isinstance(conf, bool) or not isinstance(conf, (int, float)) or not math.isfinite(conf) or conf < 0.0:
                # Corrupted or non-finite confidence: fail closed by treating as maximum confidence (1.0)
                conf = 1.0
            total_weighted += weight * conf

        # Normalized non-linear saturation curve: 1 - exp(-total_weighted)
        leakage = 1.0 - math_exp(-total_weighted)
        return min(1.0, max(0.0, leakage))

    def evaluate_disclosure(
        self,
        estimated_utility_gain: float,
        detections: List[DetectionResult],
        custom_threshold: Optional[float] = None
    ) -> MPUResult:
        import math
        if isinstance(estimated_utility_gain, bool) or not isinstance(estimated_utility_gain, (int, float)):
            raise TypeError(f"estimated_utility_gain must be numeric, got {type(estimated_utility_gain).__name__}")
        if not math.isfinite(estimated_utility_gain):
            raise ValueError(f"estimated_utility_gain must be finite, got {estimated_utility_gain}")

        if custom_threshold is not None:
            if isinstance(custom_threshold, bool) or not isinstance(custom_threshold, (int, float)):
                raise TypeError(f"custom_threshold must be numeric, got {type(custom_threshold).__name__}")
            if not math.isfinite(custom_threshold) or custom_threshold < 0.0:
                raise ValueError(f"custom_threshold must be a finite non-negative number, got {custom_threshold}")
            threshold = float(custom_threshold)
        else:
            threshold = self.min_mpu_threshold

        delta_u = max(0.0, min(1.0, float(estimated_utility_gain)))
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
