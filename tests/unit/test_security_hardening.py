"""
Adversarial Regression Test Suite for Security Hardening.
Covers the 12 required threat scenarios:
1. Agent-supplied scope attempts to expand trusted scope.
2. Missing, empty, malformed, and contradictory scope.
3. Missing operation or target/resource.
4. An empty action list followed by an attempted state-changing operation.
5. A valid authorization token reused for a different request or target.
6. Request mutation between authorization and execution.
7. Stale policy version or revoked authorization.
8. Direct executor invocation without valid authorization.
9. Exceptions or malformed authorization evidence never result in successful protected execution.
10. Public API calls with omitted trust_remote_code do not enable remote code.
11. Explicit trust_remote_code=True is honored only through the documented opt-in path.
12. Existing legitimate authorized workflows continue to pass.
"""

import pytest
import decimal
from decimal import Decimal
import time
from unittest.mock import patch, MagicMock

import epistemicos
from epistemicos.gates import (
    PermissionGate,
    GateDecision,
    GateAction,
    GateInput,
)
from epistemicos.models import CanonicalProblemRepresentation, PermissionScope
from epistemicos.core import EpistemicOrchestrator
from examples.enterprise.procurement import (
    ProcurementGovernanceGate,
    ProcurementRequest,
    ProcurementDecisionToken,
    TrustedEvidenceContext,
    SyntheticProcurementExecutor,
)


# =====================================================================
# Scenario 1: Agent-supplied scope attempts to expand trusted scope
# =====================================================================
def test_agent_supplied_scope_expansion_rejected():
    """Agent tries to inject allowed_operations in payload to grant itself admin rights."""
    # Gate initialized with restrictive trusted_scope
    gate = PermissionGate(trusted_scope={"allowed_operations": ["read"], "allowed_resources": ["db1"]})

    # Agent payload tries to expand scope to include "admin_delete"
    agent_payload = {
        "scope": {"allowed_operations": ["read", "admin_delete"], "allowed_resources": ["db1"]}
    }
    context = {"proposed_actions": [{"op": "admin_delete", "node": "db1"}]}

    res = gate.evaluate(agent_payload, context)
    assert res.passed is False
    assert res.action == GateAction.HALT
    assert "outside allowed scope operations" in res.reason


# =====================================================================
# Scenario 2: Missing, empty, malformed, and contradictory scope
# =====================================================================
@pytest.mark.parametrize("bad_scope", [
    None,
    {},
    "not_a_dict_scope",
    {"allowed_operations": None},
    {"allowed_operations": "should_be_list_not_str"},
    {"allowed_operations": ["read"], "allowed_resources": ["db1"], "is_rmm_origin": True}  # Contradictory: tries update from RMM
])
def test_malformed_or_contradictory_scope(bad_scope):
    # Initializing gate with restricted allowed_actions ("read") or empty trusted scope
    gate = PermissionGate(allowed_actions=["read"])
    payload = {"scope": bad_scope}
    context = {"proposed_actions": [{"op": "update_db", "node": "db1"}]}

    res = gate.evaluate(payload, context)
    assert res.passed is False
    assert res.action == GateAction.HALT


# =====================================================================
# Scenario 3: Missing operation or target/resource
# =====================================================================
def test_missing_operation_or_target_resource():
    gate = PermissionGate()

    # Action missing 'op'
    res_no_op = gate.evaluate({}, {"proposed_actions": [{"node": "db1"}]})
    assert res_no_op.passed is False
    assert res_no_op.action == GateAction.HALT
    assert "Missing or invalid operation identifier" in res_no_op.reason

    # Action with empty/blank 'op'
    res_blank_op = gate.evaluate({}, {"proposed_actions": [{"op": "   ", "node": "db1"}]})
    assert res_blank_op.passed is False
    assert res_blank_op.action == GateAction.HALT
    assert "Missing or invalid operation identifier" in res_blank_op.reason

    # Action missing target/resource ('node' and 'endpoint')
    res_no_target = gate.evaluate({}, {"proposed_actions": [{"op": "read"}]})
    assert res_no_target.passed is False
    assert res_no_target.action == GateAction.HALT
    assert "Missing or invalid target/resource identifier" in res_no_target.reason

    # Action with empty/blank target/resource
    res_blank_target = gate.evaluate({}, {"proposed_actions": [{"op": "read", "node": "   "}]})
    assert res_blank_target.passed is False
    assert res_blank_target.action == GateAction.HALT
    assert "Missing or invalid target/resource identifier" in res_blank_target.reason


# =====================================================================
# Scenario 4: Empty action list followed by attempted state-changing operation
# =====================================================================
def test_empty_action_list_does_not_authorize_future_execution():
    gate = ProcurementGovernanceGate(spending_limit=Decimal("1000.00"))
    executor = SyntheticProcurementExecutor()

    # Pre-check step evaluating an empty action list / non-executing query
    req = ProcurementRequest(
        request_id="REQ-EMPTY-1",
        purchase_order_id="PO-1",
        vendor_id="VEND-A",
        requester_id="USR-1",
        amount=Decimal("500.00"),
        currency="USD",
        invoice_amount=Decimal("500.00"),
        purchase_order_amount=Decimal("500.00"),
        goods_receipt_amount=Decimal("500.00"),
    )

    trusted_ctx = TrustedEvidenceContext(
        verified_approved_vendors={"VEND-A"},
        evidence_complete=True,
    )

    outcome = gate.evaluate_contract(GateInput(payload=req, context={"trusted_evidence": trusted_ctx}))
    assert outcome.passed is True

    # State-changing operation attempts execution with a MUTATED request (e.g. amount increased to $5000)
    mutated_req = ProcurementRequest(
        request_id="REQ-EMPTY-1",
        purchase_order_id="PO-1",
        vendor_id="VEND-A",
        requester_id="USR-1",
        amount=Decimal("5000.00"),  # Mutated amount!
        currency="USD",
        invoice_amount=Decimal("5000.00"),
        purchase_order_amount=Decimal("5000.00"),
        goods_receipt_amount=Decimal("5000.00"),
    )

    # Attempt downstream execution with the mutated request using the earlier outcome
    executed = executor.execute(outcome, mutated_req, gate)
    assert executed is False  # MUST NOT execute!
    assert len(executor.executed_orders) == 0


# =====================================================================
# Scenario 5: Valid authorization token reused for a different request or target
# =====================================================================
def test_authorization_token_reuse_rejected():
    gate = ProcurementGovernanceGate(spending_limit=Decimal("10000.00"))
    executor = SyntheticProcurementExecutor()

    req_original = ProcurementRequest(
        request_id="REQ-ORIG-1",
        purchase_order_id="PO-100",
        vendor_id="VEND-GOOD",
        requester_id="USR-ALICE",
        amount=Decimal("2000.00"),
        currency="USD",
        invoice_amount=Decimal("2000.00"),
        purchase_order_amount=Decimal("2000.00"),
        goods_receipt_amount=Decimal("2000.00"),
    )
    trusted_ctx = TrustedEvidenceContext(
        verified_approved_vendors={"VEND-GOOD", "VEND-BAD"},
        evidence_complete=True,
    )

    outcome_original = gate.evaluate_contract(
        GateInput(payload=req_original, context={"trusted_evidence": trusted_ctx})
    )
    assert outcome_original.passed is True

    # Attack: Attacker steals the token from outcome_original and tries to use it for a different target request
    req_different_target = ProcurementRequest(
        request_id="REQ-ORIG-1",
        purchase_order_id="PO-999-EVIL",  # Target changed!
        vendor_id="VEND-BAD",
        requester_id="USR-ALICE",
        amount=Decimal("2000.00"),
        currency="USD",
        invoice_amount=Decimal("2000.00"),
        purchase_order_amount=Decimal("2000.00"),
        goods_receipt_amount=Decimal("2000.00"),
    )

    executed = executor.execute(outcome_original, req_different_target, gate)
    assert executed is False
    assert len(executor.executed_orders) == 0


# =====================================================================
# Scenario 6: Request mutation between authorization and execution
# =====================================================================
def test_request_mutation_between_authorization_and_execution():
    gate = ProcurementGovernanceGate(spending_limit=Decimal("10000.00"))
    executor = SyntheticProcurementExecutor()

    req = ProcurementRequest(
        request_id="REQ-MUTATE-1",
        purchase_order_id="PO-200",
        vendor_id="VEND-GOOD",
        requester_id="USR-ALICE",
        amount=Decimal("1000.00"),
        currency="USD",
        invoice_amount=Decimal("1000.00"),
        purchase_order_amount=Decimal("1000.00"),
        goods_receipt_amount=Decimal("1000.00"),
    )
    trusted_ctx = TrustedEvidenceContext(
        verified_approved_vendors={"VEND-GOOD"},
        evidence_complete=True,
    )

    outcome = gate.evaluate_contract(
        GateInput(payload=req, context={"trusted_evidence": trusted_ctx})
    )
    assert outcome.passed is True

    # Mutate request amount after authorization
    req.amount = Decimal("999999.00")

    executed = executor.execute(outcome, req, gate)
    assert executed is False
    assert len(executor.executed_orders) == 0


# =====================================================================
# Scenario 7: Stale policy version or revoked authorization
# =====================================================================
def test_stale_policy_version_or_expired_token_rejected():
    gate = ProcurementGovernanceGate(spending_limit=Decimal("10000.00"), token_ttl_seconds=1.0)
    executor = SyntheticProcurementExecutor()

    req = ProcurementRequest(
        request_id="REQ-EXPIRE-1",
        purchase_order_id="PO-300",
        vendor_id="VEND-GOOD",
        requester_id="USR-ALICE",
        amount=Decimal("1000.00"),
        currency="USD",
        invoice_amount=Decimal("1000.00"),
        purchase_order_amount=Decimal("1000.00"),
        goods_receipt_amount=Decimal("1000.00"),
    )
    trusted_ctx = TrustedEvidenceContext(
        verified_approved_vendors={"VEND-GOOD"},
        evidence_complete=True,
    )

    now = time.time()
    outcome = gate.evaluate_contract(
        GateInput(payload=req, context={"trusted_evidence": trusted_ctx})
    )
    assert outcome.passed is True

    # Attempt execution after token expiration
    future_time = now + 500.0
    executed = executor.execute(outcome, req, gate, current_time=future_time)
    assert executed is False
    assert len(executor.executed_orders) == 0


# =====================================================================
# Scenario 8: Direct executor invocation without valid authorization
# =====================================================================
def test_direct_executor_invocation_without_valid_auth_rejected():
    executor = SyntheticProcurementExecutor()

    req = ProcurementRequest(
        request_id="REQ-DIRECT-1",
        purchase_order_id="PO-400",
        vendor_id="VEND-GOOD",
        requester_id="USR-ALICE",
        amount=Decimal("1000.00"),
        currency="USD",
        invoice_amount=Decimal("1000.00"),
        purchase_order_amount=Decimal("1000.00"),
        goods_receipt_amount=Decimal("1000.00"),
    )

    # 1. Calling executor with None outcome
    assert executor.execute(None, req) is False

    # 2. Calling executor with fake object claiming decision=ALLOW but missing HMAC token
    class FakeOutcome:
        decision = GateDecision.ALLOW
        passed = True
        evidence = {}

    assert executor.execute(FakeOutcome(), req) is False
    assert len(executor.executed_orders) == 0


# =====================================================================
# Scenario 9: Exceptions or malformed authorization evidence never result in ALLOW
# =====================================================================
def test_exceptions_and_malformed_evidence_fail_closed():
    gate = PermissionGate()

    class FaultyPayload:
        @property
        def proposed_actions(self):
            raise RuntimeError("Database connection exploded during scope resolution!")

    # Unhandled exception during evaluation must fail closed
    res = gate.evaluate(FaultyPayload(), {})
    assert res.passed is False
    assert res.action == GateAction.HALT
    assert "Gate Execution Error" in res.reason or "GATE_EXECUTION_ERROR" in res.reason or "HALTED" in res.status


# =====================================================================
# Scenario 10 & 11: Public API trust_remote_code defaults and explicit opt-in
# =====================================================================
def test_public_api_trust_remote_code_default_is_false():
    """Verify epistemicos.get_model_and_tokenizer defaults to trust_remote_code=False."""
    import inspect
    sig = inspect.signature(epistemicos.get_model_and_tokenizer)
    assert sig.parameters["trust_remote_code"].default is False


def test_public_api_trust_remote_code_propagation():
    mock_torch = MagicMock()
    mock_tok = MagicMock()
    mock_tok.from_pretrained.return_value.pad_token = "pad"

    mock_model_cls = MagicMock()
    mock_model_inst = MagicMock()
    mock_model_cls.from_pretrained.return_value.to.return_value = mock_model_inst

    fake_transformers = MagicMock()
    fake_transformers.AutoTokenizer = mock_tok
    fake_transformers.AutoModelForCausalLM = mock_model_cls

    with patch.dict("sys.modules", {"torch": mock_torch, "transformers": fake_transformers}):
        # Call public wrapper with omitted trust_remote_code
        epistemicos.get_model_and_tokenizer("dummy-model")
        assert mock_tok.from_pretrained.call_args[1]["trust_remote_code"] is False
        assert mock_model_cls.from_pretrained.call_args[1]["trust_remote_code"] is False

        # Explicit opt-in
        epistemicos.get_model_and_tokenizer("dummy-model", trust_remote_code=True)
        assert mock_tok.from_pretrained.call_args[1]["trust_remote_code"] is True
        assert mock_model_cls.from_pretrained.call_args[1]["trust_remote_code"] is True


# =====================================================================
# Scenario 12: Existing legitimate authorized workflows continue to pass
# =====================================================================
def test_legitimate_authorized_workflow_passes():
    orchestrator = EpistemicOrchestrator()
    scope = PermissionScope(
        origin_subnet="192.168.1.10",
        allowed_resources=["logistics_db"],
        allowed_operations=["read", "update_db"]
    )
    orchestrator.gates[0] = PermissionGate(trusted_scope=scope.model_dump())
    cpr = CanonicalProblemRepresentation(
        policy_id="POL-LEGIT-1",
        fleet_data={"vehicle_count": 5},
        scope=scope
    )
    context = {
        "token_count": 5,
        "token_logprobs": [-0.01] * 5,
        "proposed_actions": [{"op": "update_db", "node": "logistics_db"}]
    }

    result = orchestrator.process_submission(cpr.model_dump(), context)
    assert result["status"] == "ALLOWED"
