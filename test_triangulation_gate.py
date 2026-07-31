import json
import random
from epistemicos.engine import EpistemicOrchestrator
from epistemicos.gates import TriangulationGate, EntropyGate, PermissionGate
from epistemicos.cpr import CanonicalProblemRepresentation

def test_triangulation_gate():
    print("Testing TriangulationGate: Data Washing Defense...\n")

    # 1. Setup the orchestrator with required gates
    os = EpistemicOrchestrator(prior_probabilities={"clean": 0.5, "washed": 0.5})
    os.register_gate("EntropyGate", EntropyGate(z_threshold=2.85))
    os.register_gate("PermissionGate", PermissionGate(contract_model=CanonicalProblemRepresentation))
    os.register_gate("TriangulationGate", TriangulationGate(max_divergence_threshold=0.15))

    # Standard testing variables
    mock_likelihoods = {"clean": 0.8, "washed": 0.2}
    safe_logprobs = [random.uniform(-0.05, -0.01) for _ in range(15)]
    proposed_actions = []

    # --- Scenario A: Clean Submission ---
    print("--- SCENARIO A: CLEAN SUBMISSION ---")
    clean_payload = {
        "policy_id": "SENSOR-4A-CLEAN",
        "fleet_data": {"vehicle_count": 10, "operating_radius_miles": 100.0, "hazard_class": "standard"},
        "primary_metric": 100.0,
        "heterogeneous_telemetry": [98.5, 102.0, 101.1]
    }

    clean_res = os.process_submission(
        raw_payload=clean_payload,
        likelihoods=mock_likelihoods,
        token_logprobs=safe_logprobs,
        proposed_actions=proposed_actions
    )

    # Locate the specific gate evaluation in the event log
    clean_gate_eval = next(event for event in clean_res["receipt"]["event_log"] if event["type"] == "GateEvaluated:TriangulationGate")
    print("Clean Result:", json.dumps(clean_gate_eval["details"], indent=2))

    if clean_gate_eval["details"]["passed"]:
        print("  SUCCESS: Clean submission verified and passed.")
    else:
        print("  FAIL: Clean submission incorrectly failed.")

    # --- Scenario B: Washed Submission ---
    print("\n--- SCENARIO B: WASHED/MANIPULATED SUBMISSION ---")
    washed_payload = {
        "policy_id": "SENSOR-4A-WASHED",
        "fleet_data": {"vehicle_count": 10, "operating_radius_miles": 100.0, "hazard_class": "standard"},
        "primary_metric": 150.0,  # Artificially inflated
        "heterogeneous_telemetry": [98.5, 102.0, 101.1]
    }

    washed_res = os.process_submission(
        raw_payload=washed_payload,
        likelihoods=mock_likelihoods,
        token_logprobs=safe_logprobs,
        proposed_actions=proposed_actions
    )

    washed_gate_eval = next(event for event in washed_res["receipt"]["event_log"] if event["type"] == "GateEvaluated:TriangulationGate")
    print("Washed Result:", json.dumps(washed_gate_eval["details"], indent=2))

    if washed_gate_eval["details"]["passed"]:
        print("  CRITICAL FAILURE: Washed data bypassed the TriangulationGate!")
    else:
        print("  DEFENSE SUCCESSFUL: TriangulationGate tripped and rejected the manipulated data.")

if __name__ == "__main__":
    test_triangulation_gate()
