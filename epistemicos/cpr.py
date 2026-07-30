import time
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field, ValidationError

class PermissionScope(BaseModel):
    """Cryptographic-style boundary for delegated agent actions."""
    allowed_resources: List[str] = Field(default_factory=list)
    allowed_operations: List[str] = Field(default_factory=list)
    expires_at: float = Field(default_factory=lambda: time.time() + 15.0)
    max_attempts: int = Field(default=3)
    attempt_count: int = Field(default=1)

    # SaaS Egress Governors
    max_payload_bytes: int = Field(default=4096)
    max_row_count: int = Field(default=50)

    # Downstream Scope Lock (RMM / Vendor Subnet Quarantine)
    origin_subnet: Optional[str] = None
    is_rmm_origin: bool = False
    quarantine_subnets: List[str] = Field(
        default_factory=lambda: ["10.240.", "172.16.rmm", "msp_bridge", "vendor_portal"]
    )

    def is_quarantined_channel(self) -> bool:
        """Determines if the transaction originates from a high-risk vendor or RMM subnet."""
        if self.is_rmm_origin:
            return True
        if self.origin_subnet:
            return any(prefix in self.origin_subnet for prefix in self.quarantine_subnets)
        return False

    def validate_action(self, action: Dict[str, Any]) -> bool:
        """Evaluates if a proposed action is within the permitted scope, timeline, and retry limits."""
        if self.attempt_count > self.max_attempts or time.time() > self.expires_at:
            return False

        op = action.get("op")

        # 1. Downstream Scope Lock: Enforce Read-Only Quarantine on RMM/Vendor Channels
        if self.is_quarantined_channel():
            mutating_operations = {
                "update_db", "write_db", "reroute_freight", "halt_payments",
                "issue_binder", "bind_policy", "cancel_policy", "release_buffer"
            }
            if op in mutating_operations:
                return False  # Dynamically block state-changing operations

        # 2. Operations Whitelist Check
        if op and op not in self.allowed_operations:
            return False

        # 3. Resource Boundary Check
        target = action.get("node") or action.get("endpoint") or action.get("table")
        if target and target not in self.allowed_resources:
            return False

        return True

    def validate_egress(self, response_payload: Any) -> bool:
        """
        Evaluates recursive row/record count of the return payload.
        Neutralizes multi-million record SaaS exfiltration attempts.
        """
        import sys

        # 1. Baseline Byte Size Check
        if sys.getsizeof(str(response_payload)) > self.max_payload_bytes:
            return False

        # 2. Strict SaaS Row Count Check (Recursive)
        def count_max_records(data: Any) -> int:
            if isinstance(data, list):
                # Evaluate list length and recurse deeper
                return max(len(data), max((count_max_records(item) for item in data), default=0))
            elif isinstance(data, dict):
                # Evaluate dictionary key count (preventing dict-inflation evasion) and recurse
                return max(len(data.keys()), max((count_max_records(val) for val in data.values()), default=0))
            return 0

        if count_max_records(response_payload) > self.max_row_count:
            return False

        return True

class CanonicalProblemRepresentation(BaseModel):
    """
    Standardized payload format for EpistemicOS.
    Normalizes inputs and enforces strict authorization boundaries.
    """
    policy_id: str
    fleet_data: Optional[Dict[str, Any]] = None
    risk_details: Optional[Dict[str, Any]] = None
    primary_metric: Optional[float] = None
    scope: PermissionScope = Field(default_factory=PermissionScope)

    def __init__(self, **data):
        super().__init__(**data)
        # Dynamically bind scope based on payload context if not explicitly provided
        if not data.get("scope"):
            self.scope = PermissionScope(
                allowed_resources=["logistics_db", "risk_profiles", "/underwriting/flag", "/bind_policy", "/cancel_policy", "/issue_binder"],
                allowed_operations=["read", "query", "update_db", "write_db", "send_api_alert", "api_call", "issue_binder", "revert", "remove", "replace", "rescind_binder"]
            )

    def serialize_for_belief_kernel(self) -> List[float]:
        """
        Converts the raw data into a numerical vector for the Bayesian Kernel.
        (Simplified implementation for current testing phases).
        """
        if self.fleet_data:
            # Example extraction: normalize vehicle count and radius
            v_count = self.fleet_data.get("vehicle_count", 0) / 100.0
            radius = self.fleet_data.get("operating_radius_miles", 0) / 1000.0
            loss_mod = self.fleet_data.get("loss_modifier", 1.0)
            return [v_count, radius, loss_mod]
        elif self.risk_details:
            loss_mod = self.risk_details.get("loss_ratio_3yr", self.risk_details.get("loss_mod", 1.0))
            return [self.primary_metric or 0.0, loss_mod]
        return [0.0, 0.0, 0.0]
