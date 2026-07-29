from pydantic import BaseModel, Field
from typing import List, Optional

class FleetProfile(BaseModel):
    vehicle_count: int = Field(..., gt=0, description="Total number of vehicles in the commercial fleet.")
    operating_radius_miles: float = Field(..., ge=0.0, description="Maximum operational radius in miles.")
    loss_modifier: float = Field(..., gt=0.0, description="Experience rating modification factor (loss-mod).")
    hazard_class: str = Field(..., description="Primary hazard classification code.")
    garaging_states: List[str] = Field(..., description="List of primary states where fleet units are garaged.")

class CanonicalProblemRepresentation(BaseModel):
    policy_id: str = Field(..., description="Unique enterprise identifier for the policy submission.")
    line_of_business: str = Field(default="commercial_auto", description="Active insurance line of business.")
    fleet_data: FleetProfile = Field(..., description="Normalized underwriting telemetry for the fleet.")
    raw_payload_hash: Optional[str] = Field(default=None, description="Cryptographic hash of the raw incoming payload for auditing.")

    def serialize_for_belief_kernel(self) -> dict:
        """Exports normalized features into a flat numerical vector for downstream Bayesian updates."""
        return {
            "vehicles": self.fleet_data.vehicle_count,
            "radius": self.fleet_data.operating_radius_miles,
            "loss_mod": self.fleet_data.loss_modifier
        }
