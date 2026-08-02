# epistemicos/domain/logistics.py

import hashlib
from typing import Dict, Any, List, Set
from pydantic import BaseModel, Field
from epistemicos.cpr import PermissionScope

class SupplyChainNodeRepresentation(BaseModel):
    """
    Standardized payload representation for supply chain node risk evaluation.
    Converts domain logistics telemetry into normalized belief-kernel inputs and applies
    Just-In-Time (JIT) egress masking.
    """
    node_id: str
    logistics_data: Dict[str, Any] = Field(default_factory=dict)
    scope: PermissionScope = Field(
        default_factory=lambda: PermissionScope(
            allowed_resources=["/routing_db", "/supplier_portal", "/inventory_api"],
            allowed_operations=[
                "read", "query", "reroute_freight", 
                "halt_payments", "release_buffer", "revert_routing"
            ]
        )
    )
    math_whitelist: Set[str] = Field(
        default_factory=lambda: {"inventory_buffer_days", "node_criticality", "downstream_dependencies"}
    )

    def serialize_for_belief_kernel(self) -> List[float]:
        """Normalizes raw logistics metrics into bounded scalar features [0.0, 1.0]."""
        buffer_ratio = min(self.logistics_data.get("inventory_buffer_days", 0) / 30.0, 1.0)
        criticality_score = min(self.logistics_data.get("node_criticality", 1.0) / 10.0, 1.0)
        return [buffer_ratio, criticality_score]

    def mask_egress_payload(self, raw_db_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Intercepts outbound database payloads and redacts non-whitelisted attributes,
        anonymizing identifiers while maintaining referential integrity.
        """
        masked_payload = {}

        for key, value in raw_db_payload.items():
            if key in self.math_whitelist or key == "status":
                masked_payload[key] = value
            elif "supplier" in key or "vendor" in key:
                hashed = hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:8]
                masked_payload[key] = f"ANON_ENTITY_{hashed.upper()}"
            else:
                masked_payload[key] = "[REDACTED_BY_EPISTEMICOS]"

        return masked_payload