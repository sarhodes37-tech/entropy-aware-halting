import json
from epistemicos.engine import EpistemicEngine

def test_brute_force_retry():
    priors = {"preferred": 0.5, "standard": 0.3, "substandard": 0.2}
    engine = EpistemicEngine(prior_probabilities=priors)

    proposed_actions = [
        {
            "action": {"op": "api_call", "endpoint": "/issue_binder", "data": "POL-2026-LOOP"},
            "rollback": {"op": "api_call", "endpoint": "/cancel_policy", "data": "POL-2026-LOOP"}
        }
    ]

    mock_payload_base = {
        "policy_id": "POL-2026-LOOP",
        "fleet_data": {
            "vehicle_count": 10,
            "operating_radius_miles": 150.0,
            "loss_modifier": 1.0,
            "hazard_class": "standard",
            "garaging_states": ["VA"]
        }
    }

    mock_likelihoods = {"preferred": 0.4, "standard": 0.5, "substandard": 0.1}

    # Simulating highly confident tokens (the agent is absolutely sure it should do this)
    safe_logprobs = [-0.01, -0.02, -0.01, -0.05, -0.03, -0.01, -0.02, -0.04, -0.01, -0.02]

    print("Testing High-Frequency Retry Vulnerability...\n")

    for attempt in range(1, 5):
        print(f"--- Attempt {attempt} ---")

        # Inject the current attempt count into the payload's scope
        mock_payload = mock_payload_base.copy()
        mock_payload["scope"] = {
            "max_attempts": 3,
            "attempt_count": attempt,
            "allowed_resources": ["/issue_binder", "/cancel_policy"],
            "allowed_operations": ["api_call"]
        }

        result = engine.process_submission(
            raw_payload=mock_payload,
            likelihoods=mock_likelihoods,
            token_logprobs=safe_logprobs,
            proposed_actions=proposed_actions
        )

        if result["execution_approved"]:
            print("✅ Execution Approved.")
        else:
            print(f"🛑 Execution Halted. Scope validation failed.")
            print(f"🔄 Rollbacks executed: {len(result['rollbacks_executed'])}")
        print("")

if __name__ == "__main__":
    test_brute_force_retry()
