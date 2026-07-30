import json
from logistics_cpr import SupplyChainNodeRepresentation

def test_data_exfiltration_defense():
    print("Testing EpistemicOS JIT Data Masking...\n")

    # 1. The highly sensitive raw data returned from the enterprise database
    raw_enterprise_data = {
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

    print("--- RAW DATABASE EGRESS (VULNERABLE) ---")
    print(json.dumps(raw_enterprise_data, indent=2))

    # 2. Initialize the contract model
    cpr = SupplyChainNodeRepresentation(
        node_id=raw_enterprise_data["node_id"],
        logistics_data=raw_enterprise_data
    )

    # 3. Mask the payload before it ever touches the AI agent's context window
    safe_agent_payload = cpr.mask_egress_payload(raw_enterprise_data)

    print("\n--- JIT MASKED PAYLOAD (AGENT CONTEXT) ---")
    print(json.dumps(safe_agent_payload, indent=2))

    # 4. Prove the math still works
    print("\n--- BAYESIAN KERNEL SERIALIZATION ---")
    print(f"Serialized Features: {cpr.serialize_for_belief_kernel()}")

    # 5. Egress Size Check
    import sys
    raw_size = sys.getsizeof(str(raw_enterprise_data))
    masked_size = sys.getsizeof(str(safe_agent_payload))
    print(f"\nPayload Size Reduction: {raw_size} bytes -> {masked_size} bytes")

if __name__ == "__main__":
    test_data_exfiltration_defense()
