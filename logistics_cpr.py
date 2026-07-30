import time
from typing import Dict, Any, List
from pydantic import BaseModel, Field

class PermissionScope(BaseModel):
    """Cryptographic-style boundary for delegated agent actions in logistics."""
    allowed_resources: List[str] = Field(default_factory=list)
    allowed_operations: List[str] = Field(default_factory=list)
    expires_at: float = Field(default_factory=lambda: time.time() + 15.0)
    max_attempts: int = Field(default=3)
    attempt_count: int = Field(default=1)

    def validate_action(self, action: Dict[str, Any]) -> bool:
        if self.attempt_count > self.max_attempts or time.time() > self.expires_at:
            return False

        op = action.get("op")
        if op and op not in self.allowed_operations:
            return False

        target = action.get("node") or action.get("endpoint")
        if target and target not in self.allowed_resources:
            return False

        return True

class SupplyChainNodeRepresentation(BaseModel):
    """
    Standardized payload format for modeling supply chain vulnerabilities.
    Normalizes inputs to effectively price the contagion risk of a node failure.
    """
    node_id: str
    logistics_data: Dict[str, Any]
    scope: PermissionScope = Field(default_factory=PermissionScope)

    def __init__(self, **data):
        super().__init__(**data)
        if not data.get("scope"):
            self.scope = PermissionScope(
                allowed_resources=["/routing_db", "/supplier_portal", "/inventory_api"],
                allowed_operations=["reroute_freight", "halt_payments", "release_buffer", "revert_routing"]
            )

    def serialize_for_belief_kernel(self) -> List[float]:
        buffer = self.logistics_data.get("inventory_buffer_days", 0) / 30.0
        criticality = self.logistics_data.get("node_criticality", 1.0) / 10.0
        return [buffer, criticality]
