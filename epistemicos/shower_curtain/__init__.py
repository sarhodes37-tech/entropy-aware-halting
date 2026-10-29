"""
Shower Curtain Privacy Engine Package for EpistemicOS.
Local-First Privacy Mediation Subsystem.
"""

from epistemicos.shower_curtain.detector import SensitiveDataDetector, SensitivityCategory, DetectionResult
from epistemicos.shower_curtain.policy import PrivacyTreatment, PrivacyPolicy, PolicyDecision
from epistemicos.shower_curtain.vault import LocalMappingVault, VaultAccessError
from epistemicos.shower_curtain.context import ContextMinimizationBroker, ContextChunk
from epistemicos.shower_curtain.mpu import MarginalPrivacyUtilityEvaluator, MPUResult
from epistemicos.shower_curtain.gate import ShowerCurtainGate
from epistemicos.shower_curtain.engine import ShowerCurtainEngine, PrivacyTransformationResult
from epistemicos.shower_curtain.adapter import ShowerCurtainOpenAIAdapter

__all__ = [
    "SensitiveDataDetector",
    "SensitivityCategory",
    "DetectionResult",
    "PrivacyTreatment",
    "PrivacyPolicy",
    "PolicyDecision",
    "LocalMappingVault",
    "VaultAccessError",
    "ContextMinimizationBroker",
    "ContextChunk",
    "MarginalPrivacyUtilityEvaluator",
    "MPUResult",
    "ShowerCurtainGate",
    "ShowerCurtainEngine",
    "PrivacyTransformationResult",
    "ShowerCurtainOpenAIAdapter"
]
