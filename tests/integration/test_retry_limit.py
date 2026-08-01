"""
Integration test suite for EpistemicOS retry-limit enforcement and 
compensating rollback execution on high-frequency retry policy breaches.
"""

import pytest
from typing import Dict, Any


# Mock objects for test isolation
class MockCPR:
    def __init__(self, **payload):
        self.scope_data = payload.get("scope", {})

    def validate_action(self, action: Dict[str, Any]) -> bool:
        max_attempts = self.scope_data.get("max_attempts", 3)
        attempt_count = self.scope_data.get("attempt_count", 1)
        return attempt_count <= max_attempts


class MockPermissionGate:
    def __init__(self, contract_model: Any):
        self.contract_model = contract_model

    def evaluate(self, payload: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        actions = context.get("proposed_actions", [])
        cpr = self.contract_model(**payload)

        for item in actions:
            action = item.get("action", {})
            if not cpr.validate_action(action):
                return {
                    "passed": False,
                    "reason": f"Scope validation failed: attempt limit exceeded",
                    "confidence": 0.0,
                }
        return {"passed": True, "confidence": 1.0}


class MockOrchestrator:
    def __init__(self):
        self.gates = {}

    def register_gate(self, name: str, gate: Any):
        self.gates[name] = gate

    def process_submission(
        self,
        raw_payload: Dict[str, Any],
        proposed_actions: list,
        **kwargs
    ) -> Dict[str, Any]:
        context = {"proposed_actions": proposed_actions}
        rollbacks_executed = []

        # Evaluate registered gates
        for name, gate in self.gates.items():
            res = gate.evaluate(raw_payload, context)
            if not res["passed"]:
                # Execute registered rollbacks on gate veto
                for action_item in proposed_actions:
                    if "rollback" in action_item:
                        rollbacks_executed.append(action_item["rollback"])

                return {
                    "receipt": {"status": "HALTED", "reason": res["reason"]},
                    "rollbacks_executed": rollbacks_executed,
                }

        return {
            "receipt": {"status": "COMMITTED"},
            "rollbacks_executed": [],
        }


# =====================================================================
# Test Cases
# =====================================================================

def test_retry_limit_exhaustion_and_rollback():
    """
    Validates that attempts 1 through 3 commit successfully, while attempt 4 
    fails CPR scope validation and triggers compensating rollbacks.
    """
    orchestrator = MockOrchestrator()
    permission_gate = MockPermissionGate(contract_model=MockCPR)
    orchestrator.register_gate("PermissionGate", permission_gate)

    proposed_actions = [
        {
            "action": {"op": "api_call", "endpoint": "/issue_binder", "data": "POL-2026-LOOP"},
            "rollback": {"op": "api_call", "endpoint": "/cancel_policy", "data": "POL-2026-LOOP"},
        }
    ]

    base_payload = {
        "policy_id": "POL-2026-LOOP",
        "fleet_data": {
            "vehicle_count": 10,
            "operating_radius_miles": 150.0,
            "garaging_states": ["VA"],
        },
    }

    # Attempts 1 through 3 must commit successfully
    for attempt in range(1, 4):
        payload = base_payload.copy()
        payload["scope"] = {"max_attempts": 3, "attempt_count": attempt}

        result = orchestrator.process_submission(
            raw_payload=payload,
            proposed_actions=proposed_actions,
        )

        assert result["receipt"]["status"] == "COMMITTED"
        assert len(result["rollbacks_executed"]) == 0

    # Attempt 4 must breach scope limits, halt, and execute rollbacks
    failed_payload = base_payload.copy()
    failed_payload["scope"] = {"max_attempts": 3, "attempt_count": 4}

    result_attempt_4 = orchestrator.process_submission(
        raw_payload=failed_payload,
        proposed_actions=proposed_actions,
    )

    assert result_attempt_4["receipt"]["status"] == "HALTED"
    assert len(result_attempt_4["rollbacks_executed"]) == 1
    assert result_attempt_4["rollbacks_executed"][0]["endpoint"] == "/cancel_policy"
