import json
import random
from epistemicos.engine import EpistemicEngine
from logistics_cpr import SupplyChainNodeRepresentation

def test_logistics_module():
    priors = {"stable": 0.6, "constrained": 0.3, "cascading_failure": 0.1}

    # Inject the logistics contract into the engine
    engine = EpistemicEngine(
        prior_probabilities=priors,
        contract_model=SupplyChainNodeRepresentation
    )

    proposed_actions = [
        {
            "action": {"op": "reroute_freight", "endpoint": "/routing_db", "data": "NODE-77A-DIVERT"},
            "rollback": {"op": "revert_routing", "endpoint": "/routing_db", "data": "NODE-77A-RESTORE"}
        }
    ]

    mock_payload = {
        "node_id": "NODE-77A-SHENZHEN",
        "logistics_data": {
            "inventory_buffer_days": 2.5,
            "node_criticality": 9.5,
            "downstream_dependencies": 14,
            "status": "port_congestion_critical"
        }
    }

    mock_likelihoods = {"stable": 0.05, "constrained": 0.25, "cascading_failure": 0.70}
    safe_logprobs = [random.uniform(-0.05, -0.01) for _ in range(15)]

    print("Testing Logistics Module: Contagion Pricing...\n")

    result = engine.process_submission(
        raw_payload=mock_payload,
        likelihoods=mock_likelihoods,
        token_logprobs=safe_logprobs,
        proposed_actions=proposed_actions
    )

    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    test_logistics_module()
