"""
Integration test suite for Downstream Scope Locking and RMM/MSP Subnet Quarantine.
Validates that PermissionGate restricts invocations from RMM/quarantined channels to 
read-only operations while blocking state-mutating actions.
"""

import pytest
from typing import Dict, Any, List


# =====================================================================
# Mock Domain & Engine Component Definitions
# =====================================================================

class MockSupplyChainNodeRepresentation:
    """Evaluates supply chain actions against network origin boundaries."""

    QUARANTINED_SUBNETS = {"10.240.12.88"}
    MUTATING_OPERATIONS = {"reroute_freight", "write", "update_buffer"}

    def __init__(self, **payload):
        self.scope = payload.get("scope", {})
        self.origin_subnet = self.scope.get("origin_subnet", "")
        self.is_rmm = self.scope.get("is_rmm_origin", False)

    def validate_action(self, action: Dict[str, Any]) -> tuple[bool, str]:
        op = action.get("op", "")
        
        # Enforce Read-Only Scope Lock if originating from quarantined RMM subnet
        if (self.origin_subnet in self.QUARANTINED_SUBNETS or self.is_rmm) and op in self.MUTATING_OPERATIONS:
            return False, f"Downstream Scope Lock: Mutating operation '{op}' prohibited from RMM quarantine subnet ({self.origin_subnet})."

        return True, "Approved"


class MockPermissionGate:
    def __init__(self, contract_model: Any):
        self.contract_model = contract_model

    def evaluate(self, payload: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        cpr = self.contract_model(**payload)
        proposed_actions = context.get("proposed_actions", [])

        for item in proposed_actions:
            action = item.get("action", {})
            allowed, reason = cpr.validate_action(action)
            if not allowed:
                return {
                    "passed": False,
                    "reason": reason,
                    "confidence": 0.0
                }

        return {"passed": True, "reason": "All proposed operations within scope.", "confidence": 1.0}


class MockEpistemicOrchestrator:
    def __init__(self):
        self.gates = {}

    def register_gate(self, name: str, gate: Any):
        self.gates[name] = gate

    def process_submission(
        self,
        raw_payload: Dict[str, Any],
        token_logprobs: List[float],
        proposed_actions: List[Dict[str, Any]],
        **kwargs
    ) -> Dict[str, Any]:
        context = {
            "token_logprobs": token_logprobs,
            "proposed_actions": proposed_actions
        }

        veto_reasons = []
        rollbacks_executed = []

        for name, gate in self.gates.items():
            res = gate.evaluate(raw_payload, context)
            if not res["passed"]:
                veto_reasons.append(res["reason"])

        if veto_reasons:
            for act in proposed_actions:
                if "rollback" in act and act["rollback"].get("op") != "none":
                    rollbacks_executed.append(act["rollback"])

            return {
                "receipt": {
                    "status": "ROLLED_BACK",
                    "veto_reasons": veto_reasons,
                    "node_id": raw_payload.get("node_id")
                },
                "rollbacks_executed": rollbacks_executed
            }

        return {
            "receipt": {
                "status": "COMMITTED",
                "node_id": raw_payload.get("node_id")
            },
            "rollbacks_executed": []
        }


# =====================================================================
# Fixtures & Test Cases
# =====================================================================

@pytest.fixture
def orchestrator():
    engine = MockEpistemicOrchestrator()
    permission_gate = MockPermissionGate(contract_model=MockSupplyChainNodeRepresentation)
    engine.register_gate("PermissionGate", permission_gate)
    return engine


def test_internal_subnet_mutating_action_permitted(orchestrator):
    """
    Validates that state-mutating requests ('reroute_freight') originating from 
    trusted internal subnets pass scope checks and commit successfully.
    """
    payload = {
        "node_id": "NODE-101-VA",
        "logistics_data": {"inventory_buffer_days": 10},
        "scope": {
            "origin_subnet": "192.168.1.50",
            "is_rmm_origin": False
        }
    }

    proposed_actions = [{
        "action": {"op": "reroute_freight", "endpoint": "/routing_db", "data": "DIVERT_NODE"},
        "rollback": {"op": "revert_routing", "endpoint": "/routing_db", "data": "RESTORE_NODE"}
    }]

    deterministic_logprobs = [-0.02] * 10

    result = orchestrator.process_submission(
        raw_payload=payload,
        token_logprobs=deterministic_logprobs,
        proposed_actions=proposed_actions
    )

    assert result["receipt"]["status"] == "COMMITTED"
    assert len(result["rollbacks_executed"]) == 0


def test_rmm_quarantine_subnet_mutating_action_blocked(orchestrator):
    """
    Validates that state-mutating requests ('reroute_freight') originating from 
    an RMM quarantine subnet trigger Downstream Scope Lock and execute rollbacks.
    """
    payload = {
        "node_id": "NODE-101-VA",
        "logistics_data": {"inventory_buffer_days": 10},
        "scope": {
            "origin_subnet": "10.240.12.88",
            "is_rmm_origin": True
        }
    }

    proposed_actions = [{
        "action": {"op": "reroute_freight", "endpoint": "/routing_db", "data": "DIVERT_NODE"},
        "rollback": {"op": "revert_routing", "endpoint": "/routing_db", "data": "RESTORE_NODE"}
    }]

    deterministic_logprobs = [-0.02] * 10

    result = orchestrator.process_submission(
        raw_payload=payload,
        token_logprobs=deterministic_logprobs,
        proposed_actions=proposed_actions
    )

    assert result["receipt"]["status"] == "ROLLED_BACK"
    assert len(result["receipt"]["veto_reasons"]) == 1
    assert "Downstream Scope Lock" in result["receipt"]["veto_reasons"][0]
    assert len(result["rollbacks_executed"]) == 1
    assert result["rollbacks_executed"][0]["op"] == "revert_routing"


def test_rmm_quarantine_subnet_read_only_permitted(orchestrator):
    """
    Validates that read-only diagnostic requests ('read') originating from 
    an RMM quarantine subnet remain permitted under the degraded privilege profile.
    """
    payload = {
        "node_id": "NODE-101-VA",
        "logistics_data": {"inventory_buffer_days": 10},
        "scope": {
            "origin_subnet": "10.240.12.88",
            "is_rmm_origin": True
        }
    }

    proposed_actions = [{
        "action": {"op": "read", "endpoint": "/routing_db", "data": "QUERY_STATUS"},
        "rollback": {"op": "none", "endpoint": "/routing_db"}
    }]

    deterministic_logprobs = [-0.02] * 10

    result = orchestrator.process_submission(
        raw_payload=payload,
        token_logprobs=deterministic_logprobs,
        proposed_actions=proposed_actions
    )

    assert result["receipt"]["status"] == "COMMITTED"
    assert len(result["rollbacks_executed"]) == 0
