"""
Stage B: Classification and Policy Evaluation for Shower Curtain.

Defines explicit, inspectable privacy treatments and configurable policy
models for governing how detected sensitive items are handled.
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
from epistemicos.shower_curtain.detector import SensitivityCategory, DetectionResult


class PrivacyTreatment(Enum):
    PASS = "PASS"
    REDACT = "REDACT"
    PSEUDONYMIZE = "PSEUDONYMIZE"
    GENERALIZE = "GENERALIZE"
    TRANSFORM = "TRANSFORM"
    BLOCK = "BLOCK"


@dataclass
class PolicyDecision:
    detection: DetectionResult
    treatment: PrivacyTreatment
    rule_id: str
    reason: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "detection": self.detection.to_dict(),
            "treatment": self.treatment.value,
            "rule_id": self.rule_id,
            "reason": self.reason,
            "metadata": self.metadata
        }


class PrivacyPolicy:
    """
    Configurable policy evaluator mapping sensitivity categories,
    destinations, tasks, and authorization contexts to privacy treatments.
    """

    DEFAULT_CATEGORY_MAPPINGS: Dict[SensitivityCategory, PrivacyTreatment] = {
        SensitivityCategory.CREDENTIAL: PrivacyTreatment.REDACT,
        SensitivityCategory.GOV_ID: PrivacyTreatment.REDACT,
        SensitivityCategory.FINANCIAL: PrivacyTreatment.REDACT,
        SensitivityCategory.EMAIL: PrivacyTreatment.PSEUDONYMIZE,
        SensitivityCategory.NAME: PrivacyTreatment.PSEUDONYMIZE,
        SensitivityCategory.PHONE: PrivacyTreatment.REDACT,
        SensitivityCategory.ADDRESS: PrivacyTreatment.GENERALIZE,
        SensitivityCategory.FILE_PATH: PrivacyTreatment.GENERALIZE,
        SensitivityCategory.IP_ADDRESS: PrivacyTreatment.GENERALIZE,
        SensitivityCategory.CUSTOM_ENTITY: PrivacyTreatment.PSEUDONYMIZE,
        SensitivityCategory.UNKNOWN: PrivacyTreatment.REDACT,
    }

    def __init__(
        self,
        category_treatments: Optional[Dict[SensitivityCategory, PrivacyTreatment]] = None,
        default_treatment: PrivacyTreatment = PrivacyTreatment.REDACT,
        allow_credentials_pass: bool = False,
        destination_rules: Optional[Dict[str, PrivacyTreatment]] = None
    ):
        self.category_treatments = dict(self.DEFAULT_CATEGORY_MAPPINGS)
        if category_treatments:
            self.category_treatments.update(category_treatments)
        self.default_treatment = default_treatment
        self.allow_credentials_pass = allow_credentials_pass
        self.destination_rules = destination_rules or {}

    def evaluate(
        self,
        detection: DetectionResult,
        destination: Optional[str] = None,
        user_authorized: bool = False
    ) -> PolicyDecision:
        cat = detection.category

        # Rule 1: Credentials & Secrets Safety Invariant
        if cat == SensitivityCategory.CREDENTIAL:
            if not self.allow_credentials_pass:
                return PolicyDecision(
                    detection=detection,
                    treatment=PrivacyTreatment.REDACT,
                    rule_id="RULE_CREDENTIAL_STRICT_REDACTION",
                    reason="Credentials and API keys must never be disclosed to remote models."
                )

        # Rule 2: Destination-specific rule
        if destination and destination in self.destination_rules:
            treatment = self.destination_rules[destination]
            return PolicyDecision(
                detection=detection,
                treatment=treatment,
                rule_id=f"RULE_DESTINATION_{destination.upper()}",
                reason=f"Applied destination-specific policy for '{destination}'."
            )

        # Rule 3: Category treatment mapping
        if cat in self.category_treatments:
            treatment = self.category_treatments[cat]
            return PolicyDecision(
                detection=detection,
                treatment=treatment,
                rule_id=f"RULE_CATEGORY_{cat.value}",
                reason=f"Applied category policy for {cat.value}."
            )

        # Rule 4: Default Fallback
        return PolicyDecision(
            detection=detection,
            treatment=self.default_treatment,
            rule_id="RULE_DEFAULT_FALLBACK",
            reason="Applied default conservative privacy treatment."
        )
