"""
Unit tests for Marginal Privacy Utility (MPU) implementation in
epistemicos.shower_curtain.mpu.
"""

import math
import pytest

from epistemicos.shower_curtain.detector import DetectionResult, SensitivityCategory
from epistemicos.shower_curtain.mpu import (
    MarginalPrivacyUtilityEvaluator,
    MPUResult,
    math_exp,
)


def test_mpu_result_dataclass():
    result = MPUResult(
        delta_u=0.8,
        delta_l=0.2,
        mpu_score=4.0,
        authorized=True,
        threshold=0.5,
        reason="Authorized test"
    )
    assert result.delta_u == 0.8
    assert result.delta_l == 0.2
    assert result.mpu_score == 4.0
    assert result.authorized is True
    assert result.threshold == 0.5
    assert result.reason == "Authorized test"


def test_math_exp_helper():
    assert math_exp(0.0) == 1.0
    assert math_exp(1.0) == math.e
    assert math_exp(-1.0) == pytest.approx(1.0 / math.e)


def test_evaluator_initialization_defaults_and_custom():
    evaluator_default = MarginalPrivacyUtilityEvaluator()
    assert evaluator_default.min_mpu_threshold == 0.5
    assert evaluator_default.epsilon == 1e-6

    evaluator_custom = MarginalPrivacyUtilityEvaluator(min_mpu_threshold=0.8, epsilon=1e-4)
    assert evaluator_custom.min_mpu_threshold == 0.8
    assert evaluator_custom.epsilon == 1e-4


def test_sensitivity_weights_mapping():
    evaluator = MarginalPrivacyUtilityEvaluator()
    expected_weights = {
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
    for category, weight in expected_weights.items():
        assert evaluator.SENSITIVITY_WEIGHTS[category] == weight


def test_estimate_privacy_leakage_empty():
    evaluator = MarginalPrivacyUtilityEvaluator()
    assert evaluator.estimate_privacy_leakage([]) == 0.0


def test_estimate_privacy_leakage_single_detection():
    evaluator = MarginalPrivacyUtilityEvaluator()
    det = DetectionResult(
        category=SensitivityCategory.CREDENTIAL,
        value="secret",
        span=(0, 6),
        confidence=1.0,
        detector_type="test"
    )

    # weight = 1.0 * confidence 1.0 = total 1.0
    # leakage = 1 - exp(-1.0) ~ 0.63212055
    expected_leakage = 1.0 - math.exp(-1.0)
    leakage = evaluator.estimate_privacy_leakage([det])
    assert leakage == pytest.approx(expected_leakage)


def test_estimate_privacy_leakage_multiple_detections_and_saturation():
    evaluator = MarginalPrivacyUtilityEvaluator()
    det1 = DetectionResult(
        category=SensitivityCategory.EMAIL,
        value="a@b.com",
        span=(0, 7),
        confidence=0.8,
        detector_type="test"
    )  # weight 0.5 * 0.8 = 0.4
    det2 = DetectionResult(
        category=SensitivityCategory.NAME,
        value="Alice",
        span=(8, 13),
        confidence=1.0,
        detector_type="test"
    )  # weight 0.4 * 1.0 = 0.4

    # total_weighted = 0.8
    # leakage = 1 - exp(-0.8)
    expected_leakage = 1.0 - math.exp(-0.8)
    leakage = evaluator.estimate_privacy_leakage([det1, det2])
    assert leakage == pytest.approx(expected_leakage)


def test_estimate_privacy_leakage_clamping():
    evaluator = MarginalPrivacyUtilityEvaluator()
    # High volume of detections causing total_weighted to be large
    detections = [
        DetectionResult(
            category=SensitivityCategory.CREDENTIAL,
            value=f"secret_{i}",
            span=(0, 10),
            confidence=1.0,
            detector_type="test"
        )
        for i in range(20)
    ]
    leakage = evaluator.estimate_privacy_leakage(detections)
    assert 0.0 <= leakage <= 1.0
    assert leakage == pytest.approx(1.0)


def test_evaluate_disclosure_utility_clamping():
    evaluator = MarginalPrivacyUtilityEvaluator()
    detections = []

    # Test clamping under 0.0 and above 1.0
    res_under = evaluator.evaluate_disclosure(estimated_utility_gain=-0.5, detections=detections)
    assert res_under.delta_u == 0.0

    res_over = evaluator.evaluate_disclosure(estimated_utility_gain=1.5, detections=detections)
    assert res_over.delta_u == 1.0


def test_evaluate_disclosure_authorized():
    evaluator = MarginalPrivacyUtilityEvaluator(min_mpu_threshold=0.5)
    det = DetectionResult(
        category=SensitivityCategory.FILE_PATH,
        value="/tmp/test",
        span=(0, 9),
        confidence=0.5,
        detector_type="test"
    )  # weight 0.3 * 0.5 = 0.15 => delta_l = 1 - exp(-0.15) ~ 0.1393

    res = evaluator.evaluate_disclosure(estimated_utility_gain=0.8, detections=[det])
    # mpu_score = 0.8 / (0.1393 + 1e-6) ~ 5.74 > 0.5 threshold
    assert res.authorized is True
    assert "satisfies threshold" in res.reason
    assert res.threshold == 0.5


def test_evaluate_disclosure_unauthorized():
    evaluator = MarginalPrivacyUtilityEvaluator(min_mpu_threshold=2.0)
    det = DetectionResult(
        category=SensitivityCategory.CREDENTIAL,
        value="sk-secret",
        span=(0, 9),
        confidence=1.0,
        detector_type="test"
    )  # delta_l = 1 - exp(-1) ~ 0.6321

    res = evaluator.evaluate_disclosure(estimated_utility_gain=0.1, detections=[det])
    # mpu_score = 0.1 / (0.6321 + 1e-6) ~ 0.158 < 2.0
    assert res.authorized is False
    assert "below required threshold" in res.reason
    assert res.threshold == 2.0


def test_evaluate_disclosure_custom_threshold():
    evaluator = MarginalPrivacyUtilityEvaluator(min_mpu_threshold=0.5)
    det = DetectionResult(
        category=SensitivityCategory.FILE_PATH,
        value="/path",
        span=(0, 5),
        confidence=0.5,
        detector_type="test"
    )

    res = evaluator.evaluate_disclosure(
        estimated_utility_gain=0.2,
        detections=[det],
        custom_threshold=5.0
    )
    assert res.threshold == 5.0
    assert res.authorized is False
    assert "below required threshold 5.00" in res.reason


def test_evaluate_disclosure_epsilon_prevents_zero_division():
    evaluator = MarginalPrivacyUtilityEvaluator(min_mpu_threshold=0.5, epsilon=1e-6)
    # No detections => delta_l = 0.0
    res = evaluator.evaluate_disclosure(estimated_utility_gain=0.5, detections=[])
    assert res.delta_l == 0.0
    # mpu_score = 0.5 / 1e-6 = 500000.0
    assert res.mpu_score == 500000.0
    assert res.authorized is True
