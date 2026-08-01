"""
Unit test suite for JIT Data Masking and Exfiltration Defense.
Validates field redaction, payload size reduction, and belief kernel feature preservation.
"""

import sys
import pytest
from epistemicos.cpr import CanonicalProblemRepresentation


@pytest.fixture
def raw_logistics_payload():
    return {
        "node_id": "NODE-77A-SHENZHEN",
        "supplier_name": "Apex Manufacturing Ltd.",
        "banking_routing": "091000019",
        "account_balance_usd": 14500000.00,
        "inventory_buffer_days": 2.5,
        "node_criticality": 9.5,
        "downstream_dependencies": 14,
        "status": "port_congestion_critical",
        "proprietary_cargo": "Lithium-Ion Battery Cores (Gen 4)"
    }


def test_jit_masking_strips_sensitive_data(raw_logistics_payload):
    """
    Validates that sensitive banking, balance, and proprietary strings are removed
    from agent egress payloads.
    """
    cpr = CanonicalProblemRepresentation(
        node_id=raw_logistics_payload["node_id"],
        raw_payload=raw_logistics_payload
    )

    masked = cpr.mask_egress_payload()

    # Core Security Assertions
    assert "banking_routing" not in masked
    assert "account_balance_usd" not in masked
    assert "proprietary_cargo" not in masked

    # Operational Metadata Assertions
    assert masked["node_id"] == "NODE-77A-SHENZHEN"
    assert masked["status"] == "port_congestion_critical"
    assert masked["balance_tier"] == "TIER_1_LIQUID"


def test_jit_masking_preserves_mathematical_features(raw_logistics_payload):
    """
    Validates that JIT redaction does not compromise numerical features required by kernel engines.
    """
    cpr = CanonicalProblemRepresentation(
        node_id=raw_logistics_payload["node_id"],
        raw_payload=raw_logistics_payload
    )

    features = cpr.serialize_for_belief_kernel()

    assert features["node_criticality"] == 9.5
    assert features["inventory_buffer_days"] == 2.5
    assert features["downstream_dependencies"] == 14.0


def test_jit_payload_size_reduction(raw_logistics_payload):
    """
    Validates that JIT masking reduces raw egress payload byte size before context injection.
    """
    cpr = CanonicalProblemRepresentation(
        node_id=raw_logistics_payload["node_id"],
        raw_payload=raw_logistics_payload
    )

    raw_size = sys.getsizeof(str(raw_logistics_payload))
    masked_size = sys.getsizeof(str(cpr.mask_egress_payload()))

    assert masked_size < raw_size
