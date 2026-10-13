import hashlib
import hmac
import math
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator
from epistemicos.models import PermissionScope


class SupplyChainNodeRepresentation(BaseModel):
    """Validated logistics features and least-privilege egress policy."""

    model_config = ConfigDict(extra="forbid", validate_default=True)

    node_id: str = Field(min_length=1, max_length=128)
    logistics_data: dict[str, Any] = Field(default_factory=dict)

    # Read-only by default. High-impact actions require separate authorization.
    scope: PermissionScope = Field(
        default_factory=lambda: PermissionScope(
            allowed_resources=[
                "/routing_db",
                "/supplier_portal",
                "/inventory_api",
            ],
            allowed_operations=["read", "query"],
        )
    )

    math_whitelist: frozenset[str] = frozenset({
        "inventory_buffer_days",
        "node_criticality",
        "downstream_dependencies",
    })

    @field_validator("node_id")
    @classmethod
    def validate_node_id(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("node_id must not be blank")
        return value

    @field_validator("logistics_data")
    @classmethod
    def validate_logistics_data(cls, data: dict[str, Any]):
        bounds = {
            "inventory_buffer_days": (0.0, 365.0),
            "node_criticality": (0.0, 10.0),
            "downstream_dependencies": (0.0, 100_000.0),
        }

        for key, (lower, upper) in bounds.items():
            if key not in data:
                continue

            value = data[key]
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"{key} must be numeric")

            if not math.isfinite(value) or not lower <= value <= upper:
                raise ValueError(
                    f"{key} must be finite and within [{lower}, {upper}]"
                )

        return data

    def serialize_for_belief_kernel(self) -> list[float]:
        """Return fixed-order, bounded features; reject missing required metrics."""
        data = self.logistics_data

        required = ("inventory_buffer_days", "node_criticality")
        missing = [key for key in required if key not in data]
        if missing:
            raise ValueError(f"Missing required metrics: {missing}")

        return [
            data["inventory_buffer_days"] / 30.0
            if data["inventory_buffer_days"] <= 30.0 else 1.0,
            data["node_criticality"] / 10.0,
        ]

    @staticmethod
    def _pseudonymize(value: str, key: bytes) -> str:
        if not key:
            raise ValueError("A non-empty pseudonymization key is required")

        digest = hmac.new(
            key, value.encode("utf-8"), hashlib.sha256
        ).hexdigest()[:24]

        return f"ENTITY_{digest.upper()}"

    def mask_egress_payload(
        self,
        raw_db_payload: dict[str, Any],
        *,
        pseudonymization_key: bytes,
    ) -> dict[str, Any]:
        """
        Default-deny egress. The caller must supply a managed secret key.
        Only approved scalar fields are disclosed.
        """
        if not isinstance(raw_db_payload, dict):
            raise TypeError("Payload must be a dictionary")

        output: dict[str, Any] = {}

        # Exact field names and types; never disclose arbitrary nested objects.
        approved_numeric = {
            "inventory_buffer_days": (0.0, 365.0),
            "node_criticality": (0.0, 10.0),
            "downstream_dependencies": (0.0, 100_000.0),
        }

        for key, value in raw_db_payload.items():
            if key in approved_numeric:
                lower, upper = approved_numeric[key]

                if (
                    isinstance(value, bool)
                    or not isinstance(value, (int, float))
                    or not math.isfinite(value)
                    or not lower <= value <= upper
                ):
                    raise ValueError(f"Invalid egress value for {key}")

                output[key] = value

            elif key == "status" and isinstance(value, str):
                # Avoid arbitrary free-text leakage.
                if value in {"operational", "degraded", "offline"}:
                    output[key] = value
                else:
                    output[key] = "[REDACTED]"

            elif key in {"supplier_id", "vendor_id"}:
                if not isinstance(value, str) or not value:
                    raise ValueError(f"Invalid identifier for {key}")

                output[key] = self._pseudonymize(
                    value, pseudonymization_key
                )

            else:
                output[key] = "[REDACTED]"

        return output