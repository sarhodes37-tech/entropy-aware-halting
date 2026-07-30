import json
import random
from epistemicos.engine import EpistemicOrchestrator
from epistemicos.gates import EntropyGate, PermissionGate
from logistics_cpr import SupplyChainNodeRepresentation

def test_downstream_scope_lock():
    print("Testing Downstream Scope Lock (RMM Subnet Quarantine)...\n")

    priors = {"stable": 0.6, "constrained": 0.3, "cascading_failure": 0.1}
    engine = EpistemicOrchestrator(
        prior_probabilities=priors,
        gates=[
            EntropyGate(z_threshold=2.85),
            PermissionGate(contract_model=SupplyChainNodeRepresentation)
        ]
    )

    # 1. Standard Internal Operation (Normal Subnet)
    standard_payload = {
        "node_id": "NODE-101-VA",
        "logistics_data": {"inventory_buffer_days": 10, "node_criticality": 3.0},
        "scope": {
            "origin_subnet": "192.168.1.50", # Internal subnet
            "allowed_resources": ["/routing_db"],
            "allowed_operations": ["read", "reroute_freight"]
        }
    }

    proposed_reroute = [{
        "action": {"op": "reroute_freight", "endpoint": "/routing_db", "data": "DIVERT_NODE"},
        "rollback": {"op": "revert_routing", "endpoint": "/routing_db", "data": "RESTORE_NODE"}
    }]

    safe_logprobs = [random.uniform(-0.05, -0.01) for _ in range(10)]

    print("--- 1. EVALUATING INTERNAL SUBNET (STANDARD ACCESS) ---")
    res_internal = engine.process_submission(
        raw_payload=standard_payload,
        likelihoods={"stable": 0.8, "constrained": 0.15, "cascading_failure": 0.05},
        token_logprobs=safe_logprobs,
        proposed_actions=proposed_reroute
    )
    if res_internal["receipt"]["status"] == "COMMITTED":
        print("  SUCCESS: Internal request allowed state-changing action ('reroute_freight').")
    else:
        print("  FAIL: Internal request was unexpectedly blocked.")

    # 2. Compromised MSP / RMM Subnet Pivot Attempt
    rmm_compromised_payload = {
        "node_id": "NODE-101-VA",
        "logistics_data": {"inventory_buffer_days": 10, "node_criticality": 3.0},
        "scope": {
            "origin_subnet": "10.240.12.88", # RMM / MSP quarantine subnet
            "is_rmm_origin": True,
            "allowed_resources": ["/routing_db"],
            "allowed_operations": ["read", "reroute_freight"]
        }
    }

    print("\n--- 2. EVALUATING RMM/MSP SUBNET (QUARANTINED CHANNEL) ---")
    res_rmm = engine.process_submission(
        raw_payload=rmm_compromised_payload,
        likelihoods={"stable": 0.8, "constrained": 0.15, "cascading_failure": 0.05},
        token_logprobs=safe_logprobs,
        proposed_actions=proposed_reroute
    )

    if res_rmm["receipt"]["status"] == "COMMITTED":
        print("  CRITICAL FAILURE: RMM pivot bypassed quarantine and executed mutating action!")
    else:
        print("  DEFENSE SUCCESSFUL: Mutating operation ('reroute_freight') blocked by Downstream Scope Lock.")

    # 3. Read-Only Diagnostics from RMM Channel Should Still Succeed
    proposed_read = [{
        "action": {"op": "read", "endpoint": "/routing_db", "data": "QUERY_STATUS"},
        "rollback": {"op": "none", "endpoint": "/routing_db"}
    }]

    print("\n--- 3. EVALUATING READ-ONLY DIAGNOSTICS FROM QUARANTINED CHANNEL ---")
    res_read = engine.process_submission(
        raw_payload=rmm_compromised_payload,
        likelihoods={"stable": 0.8, "constrained": 0.15, "cascading_failure": 0.05},
        token_logprobs=safe_logprobs,
        proposed_actions=proposed_read
    )

    if res_read["receipt"]["status"] == "COMMITTED":
        print("  SUCCESS: Read-only query approved through RMM channel.")
    else:
        print("  FAIL: Read-only query was incorrectly blocked.")

if __name__ == "__main__":
    test_downstream_scope_lock()
