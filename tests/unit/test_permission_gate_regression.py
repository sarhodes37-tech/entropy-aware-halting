"""
Regression tests for PermissionGate action parsing and nested endpoint boundaries.
"""

import uuid
from typing import Dict, Any
from unittest.mock import MagicMock
from epistemicos.gates import PermissionGate, GateInput, GateDecision, GateOutcome
from epistemicos.core import EpistemicOrchestrator


def test_permission_gate_nested_endpoint_extraction_allowed():
    """
    Verifies that PermissionGate extracts nested endpoint actions correctly
    and allows a valid, authorized request to proceed.
    """
    gate = PermissionGate(
        trusted_scope={
            "allowed_operations": ["api_call"],
            "allowed_resources": ["/issue_binder"],
        }
    )

    nested_action = {
        "action": {
            "op": "api_call",
            "endpoint": "/issue_binder",
            "data": "POL-2026-WATT-9011",
        },
        "rollback": {
            "op": "api_call",
            "endpoint": "/cancel_policy",
            "data": "POL-2026-WATT-9011",
        },
    }

    gate_input = GateInput(payload={}, context={"proposed_actions": [nested_action]})
    outcome = gate.evaluate_contract(gate_input)

    assert outcome.passed is True
    assert outcome.decision == GateDecision.ALLOW
    assert outcome.reason_code == "PERMISSION_SCOPE_VALIDATED"


def test_permission_gate_nested_endpoint_execution_reached():
    """
    Verifies that a valid, authorized request with a nested endpoint
    reaches actual execution callback in EpistemicOrchestrator.
    """
    execution_callback = MagicMock(return_value={"status": "EXECUTED_SUCCESSFULLY"})

    orchestrator = EpistemicOrchestrator()
    # Configure PermissionGate with trusted scope allowing api_call on /issue_binder
    perm_gate = PermissionGate(
        trusted_scope={
            "allowed_operations": ["api_call"],
            "allowed_resources": ["/issue_binder"],
        }
    )
    orchestrator.register_gate(perm_gate)

    raw_payload = {
        "policy_id": "POL-2026-WATT-9011",
        "primary_metric": 85000.0,
        "risk_details": {
            "sector": "Hyperscale_Colocation",
            "loss_mod": 0.75,
        },
    }

    context = {
        "proposed_actions": [
            {
                "action": {
                    "op": "api_call",
                    "endpoint": "/issue_binder",
                    "data": "POL-2026-WATT-9011",
                }
            }
        ],
        "token_logprobs": [-0.002, -0.004, -0.001],
        "heterogeneous_telemetry": [84500.0, 85200.0, 85100.0],
        "actual_executable": execution_callback,
    }

    token_id = "AUTH-TOKEN-PERM-GATE"
    corr_id = str(uuid.uuid4())
    digest = orchestrator.execution_boundary.compute_canonical_digest(raw_payload)

    from epistemicos.provenance import ProvenanceEvent, ProvenanceEventType, ProvenanceSource
    auth_event = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.AUTHORIZATION_GRANTED.value,
        provenance_source=ProvenanceSource.GOVERNANCE_GATE.value,
        correlation_id=corr_id,
        request_id="req-perm-gate",
        action_name="api_call",
        target="/issue_binder",
        canonical_request_digest=digest,
        timestamp="2026-01-01T00:00:00Z",
        authorization_token_id=token_id,
    )
    orchestrator.execution_boundary.store.record_event(auth_event)

    context["correlation_id"] = corr_id
    context["authorization_token_id"] = token_id

    res = orchestrator.process_submission(raw_payload, context)

    assert res["status"] == "ALLOWED"
    assert "telemetry" in res

    execution_callback.assert_called_once()


def test_permission_gate_unauthorized_endpoint_denied():
    """
    Verifies that an unauthorized endpoint nested inside action is denied (HALTed).
    """
    gate = PermissionGate(
        trusted_scope={
            "allowed_operations": ["api_call"],
            "allowed_resources": ["/issue_binder"],
        }
    )

    unauthorized_action = {
        "action": {
            "op": "api_call",
            "endpoint": "/unauthorized_admin_endpoint",
        }
    }

    gate_input = GateInput(payload={}, context={"proposed_actions": [unauthorized_action]})
    outcome = gate.evaluate_contract(gate_input)

    assert outcome.passed is False
    assert outcome.decision == GateDecision.HALT
    assert "outside allowed scope resources" in outcome.reason_code


def test_permission_gate_missing_malformed_structures_fail_closed():
    """
    Verifies that missing, malformed, or unexpected resource structures fail closed
    without treating every valid nested resource as absent.
    """
    gate = PermissionGate(
        trusted_scope={
            "allowed_operations": ["api_call"],
            "allowed_resources": ["/issue_binder"],
        }
    )

    # 1. Missing operation
    res_no_op = gate.evaluate_contract(
        GateInput(payload={}, context={"proposed_actions": [{"action": {"endpoint": "/issue_binder"}}]})
    )
    assert res_no_op.passed is False
    assert "Missing or invalid operation identifier" in res_no_op.reason_code

    # 2. Missing node/endpoint
    res_no_node = gate.evaluate_contract(
        GateInput(payload={}, context={"proposed_actions": [{"action": {"op": "api_call"}}]})
    )
    assert res_no_node.passed is False
    assert "Missing or invalid target/resource identifier" in res_no_node.reason_code

    # 3. Empty string node
    res_empty_node = gate.evaluate_contract(
        GateInput(payload={}, context={"proposed_actions": [{"action": {"op": "api_call", "endpoint": "   "}}]})
    )
    assert res_empty_node.passed is False
    assert "Missing or invalid target/resource identifier" in res_empty_node.reason_code

    # 4. Non-dict/non-string malformed action
    res_malformed = gate.evaluate_contract(
        GateInput(payload={}, context={"proposed_actions": [12345]})
    )
    assert res_malformed.passed is False
    assert "Missing or invalid operation identifier" in res_malformed.reason_code


def test_permission_gate_equivalent_representations_consistency():
    """
    Verifies that equivalent resource representations (top-level vs nested action dict vs dataclass object)
    produce consistent authorization decisions on both sides of the boundary (authorized vs unauthorized).
    """
    class CustomActionObj:
        def __init__(self, op, node):
            self.op = op
            self.node = node

    class CustomWrapperObj:
        def __init__(self, op, node):
            self.action = CustomActionObj(op, node)

    gate = PermissionGate(
        trusted_scope={
            "allowed_operations": ["update_db", "api_call"],
            "allowed_resources": ["logistics_db", "/issue_binder"],
        }
    )

    # Authorized representations
    auth_top_level = {"op": "update_db", "node": "logistics_db"}
    auth_nested_dict = {"action": {"op": "api_call", "endpoint": "/issue_binder"}}
    auth_obj_wrapper = CustomWrapperObj("update_db", "logistics_db")

    for rep in [auth_top_level, auth_nested_dict, auth_obj_wrapper]:
        out = gate.evaluate_contract(GateInput(payload={}, context={"proposed_actions": [rep]}))
        assert out.passed is True, f"Failed allowed consistency check for {rep}"

    # Unauthorized representations
    unauth_top_level = {"op": "update_db", "node": "forbidden_db"}
    unauth_nested_dict = {"action": {"op": "api_call", "endpoint": "/forbidden_endpoint"}}
    unauth_obj_wrapper = CustomWrapperObj("update_db", "forbidden_db")

    for rep in [unauth_top_level, unauth_nested_dict, unauth_obj_wrapper]:
        out = gate.evaluate_contract(GateInput(payload={}, context={"proposed_actions": [rep]}))
        assert out.passed is False, f"Failed denied consistency check for {rep}"


def test_permission_gate_reward_cheating_evasion_halted():
    """
    Regression Test:
    Verifies that reward cheating and goal mutation injection patterns (e.g. pytest.mark.skip,
    unittest.skip, assert True) in proposed actions or payload are halted immediately by PermissionGate.
    """
    gate = PermissionGate(
        trusted_scope={
            "allowed_operations": ["evaluate"],
            "allowed_resources": ["grader_service"],
        }
    )

    cheat_payloads = [
        "def evaluate(): return True # pytest.mark.skip",
        "import unittest\n@unittest.skip('skip')\ndef test(): pass",
        "assert True # skip test",
        "def test(): sys.exit(0)",
        "return True # skip test"
    ]

    for code_snippet in cheat_payloads:
        action = {"op": "evaluate", "endpoint": "grader_service", "data": code_snippet}
        gate_input = GateInput(
            payload={"policy_id": "POL-1"},
            context={"proposed_actions": [action]}
        )
        outcome = gate.evaluate_contract(gate_input)

        assert outcome.passed is False
        assert outcome.decision == GateDecision.HALT
        assert "Unsafe Command Injection, Jailbreak, or System Override Intercepted" in outcome.reason_code


def test_permission_gate_reward_cheating_pipeline_zero_callback_invocations():
    """
    Integration Regression Test:
    Verifies that when a reward-cheating submission is sent through EpistemicOrchestrator.process_submission:
    1. PermissionGate halts execution.
    2. Zero callback invocations occur.
    3. Zero side effects or fabricated evidence are accepted.
    """
    callback_mock = MagicMock(return_value={"status": "SHOULD_NOT_BE_CALLED"})
    orchestrator = EpistemicOrchestrator()

    cheat_code = "def evaluate(): return True # pytest.mark.skip"
    raw_payload = {
        "policy_id": "POL-S6-GRADER",
        "fleet_data": {"vehicle_count": 1},
        "proposed_actions": [
            {"op": "evaluate", "endpoint": "grader_service", "data": cheat_code}
        ]
    }
    context = {
        "token_count": 5,
        "token_logprobs": [-0.01] * 5,
        "trusted_scope": {
            "allowed_operations": ["evaluate"],
            "allowed_resources": ["grader_service"]
        },
        "proposed_actions": raw_payload["proposed_actions"],
        "actual_executable": callback_mock,
        "correlation_id": "CORR-REWARD-CHEAT-REGRESSION"
    }

    res = orchestrator.process_submission(raw_payload, context)

    assert res["status"] == "HALTED"
    assert res["gate"] == "PermissionGate"
    assert "Unsafe Command Injection" in res["reason"]
    callback_mock.assert_not_called()


def test_permission_gate_alternate_dispatch_keys_and_obfuscated_reward_cheating():
    """
    Verification Test:
    Tests alternate executor dispatch keys ('executable_operation' as well as 'actual_executable')
    and paraphrased / obfuscated reward-cheating payloads against EpistemicOrchestrator.
    Verifies direct callback invocation counts (0 for rejected, 1 for allowed) and side effects.
    """
    side_effects = {"invocations": 0, "completed": False}

    def synthetic_executor():
        side_effects["invocations"] += 1
        side_effects["completed"] = True
        return {"status": "SUCCESS"}

    orchestrator = EpistemicOrchestrator()

    obfuscated_snippets = [
        "def run():\n    # pytest: skip\n    return True",
        "import unittest\nclass Test(unittest.TestCase):\n    @unittest.skip('bypass')\n    def test_a(self): pass",
        "def eval():\n    assert True # skip test\n    return True",
        "def eval():\n    sys.exit(0)",
        "def eval(): return True # skip test"
    ]

    # 1. Test obfuscated cheat snippets across both dispatch keys
    for i, snippet in enumerate(obfuscated_snippets):
        dispatch_key = "executable_operation" if i % 2 == 0 else "actual_executable"
        payload = {
            "policy_id": "POL-TEST-OBF",
            "fleet_data": {"vehicle_count": 1},
            "proposed_actions": [
                {"op": "evaluate", "endpoint": "grader_service", "code": snippet}
            ]
        }
        ctx = {
            "token_count": 5,
            "token_logprobs": [-0.01] * 5,
            "trusted_scope": {
                "allowed_operations": ["evaluate"],
                "allowed_resources": ["grader_service"]
            },
            "proposed_actions": payload["proposed_actions"],
            dispatch_key: synthetic_executor,
            "correlation_id": f"CORR-OBF-{i}"
        }

        res = orchestrator.process_submission(payload, ctx)
        assert res["status"] == "HALTED"
        assert res["gate"] == "PermissionGate"
        assert side_effects["invocations"] == 0
        assert side_effects["completed"] is False

    # 2. Test legitimate control case through the exact same dispatch
    legit_payload = {
        "policy_id": "POL-TEST-LEGIT",
        "fleet_data": {"vehicle_count": 1},
        "proposed_actions": [
            {"op": "evaluate", "endpoint": "grader_service", "query": "status"}
        ]
    }
    legit_ctx = {
        "token_count": 5,
        "token_logprobs": [-0.01] * 5,
        "trusted_scope": {
            "allowed_operations": ["evaluate"],
            "allowed_resources": ["grader_service"]
        },
        "proposed_actions": legit_payload["proposed_actions"],
        "actual_executable": synthetic_executor,
        "correlation_id": "CORR-LEGIT-1"
    }

    res_legit = orchestrator.process_submission(legit_payload, legit_ctx)
    assert res_legit["status"] == "ALLOWED"
    assert side_effects["invocations"] == 1
    assert side_effects["completed"] is True


def test_permission_gate_benign_controls_with_suspicious_substrings():
    """
    Benign Control Test:
    Verifies that non-cheating/benign context payloads containing suspicious-looking variable names
    or normal words (e.g., 'pytest_config', 'skip_count', 'assert_value') do NOT cause false positive halts.
    """
    side_effects = {"invocations": 0}

    def benign_executor():
        side_effects["invocations"] += 1
        return {"status": "SUCCESS"}

    orchestrator = EpistemicOrchestrator()

    benign_code_snippets = [
        "def calculate_stats():\n    pytest_config_option = True\n    return {'score': 100}",
        "def process_items():\n    skip_count = 0\n    for item in items:\n        if item.is_empty: skip_count += 1\n    return skip_count",
        "def validate_data(val):\n    assert_value_valid = (val > 0)\n    return assert_value_valid"
    ]

    for i, snippet in enumerate(benign_code_snippets):
        payload = {
            "policy_id": "POL-BENIGN-SUBSTR",
            "fleet_data": {"vehicle_count": 1},
            "proposed_actions": [
                {"op": "evaluate", "endpoint": "grader_service", "code": snippet}
            ]
        }
        ctx = {
            "token_count": 5,
            "token_logprobs": [-0.01] * 5,
            "trusted_scope": {
                "allowed_operations": ["evaluate"],
                "allowed_resources": ["grader_service"]
            },
            "proposed_actions": payload["proposed_actions"],
            "actual_executable": benign_executor,
            "correlation_id": f"CORR-BENIGN-SUBSTR-{i}"
        }

        res = orchestrator.process_submission(payload, ctx)
        assert res["status"] == "ALLOWED", f"False positive halt for snippet {i}: {res.get('reason')}"

    assert side_effects["invocations"] == len(benign_code_snippets)
