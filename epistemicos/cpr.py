import time
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field, ValidationError

class PermissionScope(BaseModel):
    """Cryptographic-style boundary for delegated agent actions."""
    allowed_resources: List[str] = Field(default_factory=list)
    allowed_operations: List[str] = Field(default_factory=list)
    expires_at: float = Field(default_factory=lambda: time.time() + 15.0) # 15-second strict TTL

    def validate_action(self, action: Dict[str, Any]) -> bool:
        """Evaluates if a proposed action is within the permitted scope and timeline."""
        if time.time() > self.expires_at:
            return False

        op = action.get("op")
        if op and op not in self.allowed_operations:
            return False

        # Extract the target resource (node, endpoint, or table)
        target = action.get("node") or action.get("endpoint") or action.get("table")
        if target and target not in self.allowed_resources:
            return False

        return True

class CanonicalProblemRepresentation(BaseModel):
    """
    Standardized payload format for EpistemicOS.
    Normalizes inputs and enforces strict authorization boundaries.
    """
    policy_id: str
    fleet_data: Dict[str, Any]
    scope: PermissionScope = Field(default_factory=PermissionScope)

    def __init__(self, **data):
        super().__init__(**data)
        # Dynamically bind scope based on payload context if not explicitly provided
        if not data.get("scope"):
            self.scope = PermissionScope(
                allowed_resources=["logistics_db", "risk_profiles", "/underwriting/flag", "/bind_policy", "/cancel_policy"],
                allowed_operations=["update_db", "write_db", "send_api_alert", "api_call", "issue_binder", "revert", "remove", "replace", "rescind_binder"]
            )

    def serialize_for_belief_kernel(self) -> List[float]:
        """
        Converts the raw data into a numerical vector for the Bayesian Kernel.
        (Simplified implementation for current testing phases).
        """
        # Example extraction: normalize vehicle count and radius
        v_count = self.fleet_data.get("vehicle_count", 0) / 100.0
        radius = self.fleet_data.get("operating_radius_miles", 0) / 1000.0
        loss_mod = self.fleet_data.get("loss_modifier", 1.0)
        return [v_count, radius, loss_mod]
