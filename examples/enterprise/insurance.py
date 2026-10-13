import hashlib
import hmac
import math

from pydantic import BaseModel, ConfigDict, Field, field_validator


class CommercialPropertyRiskRepresentation(BaseModel):
    """
    Converts validated commercial-property data into bounded model features.
    This class does not approve, decline, price, or bind insurance.
    """

    model_config = ConfigDict(extra="forbid", validate_default=True)

    property_ref: str = Field(min_length=1, max_length=128)
    building_age_years: int = Field(ge=0, le=250)
    roof_age_years: int = Field(ge=0, le=150)
    protection_class: int = Field(ge=1, le=10)
    annual_claim_count: int = Field(ge=0, le=1000)
    insured_value_usd: float = Field(gt=0, le=10_000_000_000)
    occupancy_class: str
    sprinklered: bool

    @field_validator("insured_value_usd")
    @classmethod
    def validate_insured_value(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("insured_value_usd must be finite")
        return value

    @field_validator("occupancy_class")
    @classmethod
    def validate_occupancy(cls, value: str) -> str:
        allowed = {
            "office",
            "retail",
            "warehouse",
            "light_manufacturing",
            "contractor_shop",
        }

        if value not in allowed:
            raise ValueError("Unsupported occupancy class")

        return value

    def serialize_for_belief_kernel(self) -> list[float]:
        """
        Fixed-order feature vector.
        These transformations are illustrative, not actuarially calibrated.
        """
        return [
            self.building_age_years / 250.0,
            self.roof_age_years / 150.0,
            (self.protection_class - 1) / 9.0,
            min(self.annual_claim_count / 10.0, 1.0),
            math.log1p(self.insured_value_usd)
            / math.log1p(10_000_000_000),
            float(self.sprinklered),
        ]

    def mask_egress_payload(
        self,
        raw_payload: dict,
        *,
        pseudonymization_key: bytes,
    ) -> dict:
        """Release approved risk attributes, not policyholder identity or PII."""

        if not pseudonymization_key:
            raise ValueError("A pseudonymization key is required")

        result = {}
        approved = {
            "building_age_years",
            "roof_age_years",
            "protection_class",
            "annual_claim_count",
            "occupancy_class",
            "sprinklered",
        }

        for field in approved:
            if field not in raw_payload:
                continue

            # Validate disclosed attributes against the model's schema.
            candidate = {
                "property_ref": "EGRESS_VALIDATION",
                "building_age_years": raw_payload.get(
                    "building_age_years", 0
                ),
                "roof_age_years": raw_payload.get("roof_age_years", 0),
                "protection_class": raw_payload.get("protection_class", 1),
                "annual_claim_count": raw_payload.get(
                    "annual_claim_count", 0
                ),
                "insured_value_usd": raw_payload.get(
                    "insured_value_usd", 1.0
                ),
                "occupancy_class": raw_payload.get(
                    "occupancy_class", "office"
                ),
                "sprinklered": raw_payload.get("sprinklered", False),
            }

            validated = CommercialPropertyRiskRepresentation.model_validate(
                candidate
            )
            result[field] = getattr(validated, field)

        # Pseudonymize a known reference; never release raw identifiers.
        if "policy_id" in raw_payload:
            policy_id = raw_payload["policy_id"]
            if not isinstance(policy_id, str) or not policy_id:
                raise ValueError("Invalid policy_id")

            digest = hmac.new(
                pseudonymization_key,
                policy_id.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()[:24]

            result["policy_ref"] = f"POLICY_{digest.upper()}"

        # Policyholder names, addresses, tax identifiers, and unknown fields
        # are deliberately omitted rather than copied or generically serialized.
        return result