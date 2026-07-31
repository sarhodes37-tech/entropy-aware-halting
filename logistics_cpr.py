import time
import hashlib
from typing import Dict, Any, List
from pydantic import BaseModel, Field
from epistemicos.cpr import PermissionScope

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
                allowed_operations=["read", "query", "reroute_freight", "halt_payments", "release_buffer", "revert_routing"]
            )

    def serialize_for_belief_kernel(self) -> List[float]:
        buffer = self.logistics_data.get("inventory_buffer_days", 0) / 30.0
        criticality = self.logistics_data.get("node_criticality", 1.0) / 10.0
        return [buffer, criticality]

    def mask_egress_payload(self, raw_db_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Just-In-Time (JIT) Data Masking.
        Intercepts outbound database payloads and redacts everything except whitelisted mathematical variables.
        """
        masked_payload = {}

        # 1. Variables the agent mathematically requires to execute logic
        math_whitelist = ["inventory_buffer_days", "node_criticality", "downstream_dependencies"]

        for key, value in raw_db_payload.items():
            if key in math_whitelist:
                masked_payload[key] = value

            # 2. Maintain referential integrity without leaking actual corporate names
            elif key == "supplier_name":
                hashed = hashlib.sha256(str(value).encode()).hexdigest()[:8]
                masked_payload[key] = f"SUPPLIER_HASH_{hashed.upper()}"

            # 3. Safe contextual strings
            elif key == "status":
                masked_payload[key] = value

            # 4. Default Deny: Redact all other financial, personal, or proprietary data
            else:
                masked_payload[key] = "[REDACTED_BY_EPISTEMICOS]"

        return masked_payload
