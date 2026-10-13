"""
Unit tests for Procurement Governance Example Module (examples/enterprise/procurement.py).
Verifies typed inputs, deterministic governance rules, boundary/adversarial cases,
execution isolation, and audit/telemetry safety.
"""

import math
import pytest
from pydantic import ValidationError

from epistemicos.gates import (
    GateDecision,
    GateInput,
    GateAction,
    GateConfig,
    GateOutcome,
)
from epistemicos.audit import TamperEvidentAuditTrail, AuditEvent, AuditLogLevel
from examples.enterprise.procurement import (
    ProcurementRequest,
    ProcurementGovernanceGate,
    SyntheticProcurementExecutor,
    run_demo,
)


@pytest.fixture
def valid_procurement_data():
    return {
        "request_id": "REQ-100",
        "purchase_order_id": "PO-100",
        "vendor_id": "VEND-TRUSTED",
        "requester_id": "USR-ALICE",
        "amount": 5000.0,
        "currency": "USD",
        "invoice_amount": 5000.0,
        "purchase_order_amount": 5000.0,
        "goods_receipt_amount": 5000.0,
        "approved_vendor": True,
        "payment_instructions_changed": False,
        "independent_approval": False,
        "approver_id": None,
        "evidence_complete": True,
        "evidence_provenance": {"source": "ERP_SYSTEM_PROD"},
    }


def test_compliant_request_returns_allow(valid_procurement_data):
    gate = ProcurementGovernanceGate(spending_limit=10000.0)
    req = ProcurementRequest(**valid_procurement_data)
    gi = GateInput(payload=req, context={})

    outcome = gate.evaluate_contract(gi)

    assert outcome.decision == GateDecision.ALLOW
    assert outcome.passed is True
    assert outcome.reason_code == "PROCUREMENT_APPROVAL_GRANTED"
    assert outcome.evidence["request_id"] == "REQ-100"


def test_unapproved_vendor_returns_deny(valid_procurement_data):
    valid_procurement_data["approved_vendor"] = False
    gate = ProcurementGovernanceGate()
    req = ProcurementRequest(**valid_procurement_data)

    outcome = gate.evaluate_contract(GateInput(payload=req, context={}))

    assert outcome.decision == GateDecision.DENY
    assert outcome.passed is False
    assert outcome.reason_code == "UNAPPROVED_VENDOR"


def test_spending_authority_limit_exact_boundary(valid_procurement_data):
    gate = ProcurementGovernanceGate(spending_limit=10000.0)

    # Exactly at boundary: ALLOW
    valid_procurement_data["amount"] = 10000.0
    valid_procurement_data["invoice_amount"] = 10000.0
    valid_procurement_data["purchase_order_amount"] = 10000.0
    valid_procurement_data["goods_receipt_amount"] = 10000.0
    req_at_limit = ProcurementRequest(**valid_procurement_data)
    outcome_at_limit = gate.evaluate_contract(GateInput(payload=req_at_limit, context={}))

    assert outcome_at_limit.decision == GateDecision.ALLOW

    # Just above boundary: DENY
    valid_procurement_data["amount"] = 10000.01
    valid_procurement_data["invoice_amount"] = 10000.01
    valid_procurement_data["purchase_order_amount"] = 10000.01
    valid_procurement_data["goods_receipt_amount"] = 10000.01
    req_above_limit = ProcurementRequest(**valid_procurement_data)
    outcome_above_limit = gate.evaluate_contract(GateInput(payload=req_above_limit, context={}))

    assert outcome_above_limit.decision == GateDecision.DENY
    assert outcome_above_limit.reason_code == "EXCEEDS_SPENDING_AUTHORITY"


def test_exceeding_spending_authority_with_independent_approval(valid_procurement_data):
    gate = ProcurementGovernanceGate(spending_limit=10000.0)
    valid_procurement_data["amount"] = 50000.0
    valid_procurement_data["invoice_amount"] = 50000.0
    valid_procurement_data["purchase_order_amount"] = 50000.0
    valid_procurement_data["goods_receipt_amount"] = 50000.0
    valid_procurement_data["independent_approval"] = True
    valid_procurement_data["approver_id"] = "USR-BOB-MANAGER"

    req = ProcurementRequest(**valid_procurement_data)
    outcome = gate.evaluate_contract(GateInput(payload=req, context={}))

    assert outcome.decision == GateDecision.ALLOW


def test_segregation_of_duties_violation(valid_procurement_data):
    gate = ProcurementGovernanceGate(spending_limit=10000.0)
    valid_procurement_data["amount"] = 50000.0
    valid_procurement_data["invoice_amount"] = 50000.0
    valid_procurement_data["purchase_order_amount"] = 50000.0
    valid_procurement_data["goods_receipt_amount"] = 50000.0
    valid_procurement_data["independent_approval"] = True
    valid_procurement_data["approver_id"] = "USR-ALICE"  # Self-approval attempt!

    req = ProcurementRequest(**valid_procurement_data)
    outcome = gate.evaluate_contract(GateInput(payload=req, context={}))

    assert outcome.decision == GateDecision.DENY
    assert outcome.reason_code == "SEGREGATION_OF_DUTIES_VIOLATION"


def test_three_way_match_tolerance_boundaries(valid_procurement_data):
    gate = ProcurementGovernanceGate(match_tolerance=0.01)

    # Discrepancy within tolerance (0.005 <= 0.01)
    valid_procurement_data["invoice_amount"] = 5000.005
    req_within = ProcurementRequest(**valid_procurement_data)
    outcome_within = gate.evaluate_contract(GateInput(payload=req_within, context={}))
    assert outcome_within.decision == GateDecision.ALLOW

    # Discrepancy exceeding tolerance (0.02 > 0.01)
    valid_procurement_data["invoice_amount"] = 5000.02
    req_exceeded = ProcurementRequest(**valid_procurement_data)
    outcome_exceeded = gate.evaluate_contract(GateInput(payload=req_exceeded, context={}))
    assert outcome_exceeded.decision == GateDecision.DENY
    assert outcome_exceeded.reason_code == "THREE_WAY_MATCH_DISCREPANCY"


def test_payment_instruction_change_triggers_halt(valid_procurement_data):
    valid_procurement_data["payment_instructions_changed"] = True
    gate = ProcurementGovernanceGate()
    req = ProcurementRequest(**valid_procurement_data)

    outcome = gate.evaluate_contract(GateInput(payload=req, context={}))

    assert outcome.decision == GateDecision.HALT
    assert outcome.passed is False
    assert outcome.reason_code == "PAYMENT_INSTRUCTION_CHANGE_HOLD"


def test_incomplete_or_contradictory_evidence_returns_indeterminate(valid_procurement_data):
    gate = ProcurementGovernanceGate()

    # Unverifiable vendor status
    valid_procurement_data["approved_vendor"] = None
    req_unverifiable = ProcurementRequest(**valid_procurement_data)
    outcome_1 = gate.evaluate_contract(GateInput(payload=req_unverifiable, context={}))
    assert outcome_1.decision == GateDecision.INDETERMINATE
    assert outcome_1.reason_code == "UNVERIFIABLE_VENDOR_STATUS"

    # Incomplete evidence flag
    valid_procurement_data["approved_vendor"] = True
    valid_procurement_data["evidence_complete"] = False
    req_incomplete = ProcurementRequest(**valid_procurement_data)
    outcome_2 = gate.evaluate_contract(GateInput(payload=req_incomplete, context={}))
    assert outcome_2.decision == GateDecision.INDETERMINATE
    assert outcome_2.reason_code == "INCOMPLETE_EVIDENCE"

    # Contradictory independent approval evidence
    valid_procurement_data["evidence_complete"] = True
    valid_procurement_data["independent_approval"] = True
    valid_procurement_data["approver_id"] = None
    req_contradictory = ProcurementRequest(**valid_procurement_data)
    outcome_3 = gate.evaluate_contract(GateInput(payload=req_contradictory, context={}))
    assert outcome_3.decision == GateDecision.INDETERMINATE
    assert outcome_3.reason_code == "CONTRADICTORY_APPROVAL_EVIDENCE"


@pytest.mark.parametrize(
    "bad_value, expected_msg",
    [
        (True, "Booleans masquerading as numeric amounts"),
        (False, "Booleans masquerading as numeric amounts"),
        (-100.0, "strictly positive"),
        (0.0, "strictly positive"),
        (float("nan"), "finite"),
        (float("inf"), "finite"),
        (float("-inf"), "finite"),
    ],
)
def test_pydantic_amount_strict_validation(valid_procurement_data, bad_value, expected_msg):
    valid_procurement_data["amount"] = bad_value
    with pytest.raises(ValidationError) as exc_info:
        ProcurementRequest(**valid_procurement_data)
    assert expected_msg in str(exc_info.value)


def test_pydantic_currency_validation(valid_procurement_data):
    valid_procurement_data["currency"] = "BTC"
    with pytest.raises(ValidationError) as exc_info:
        ProcurementRequest(**valid_procurement_data)
    assert "Unsupported currency" in str(exc_info.value)


def test_pydantic_forbid_extra_fields(valid_procurement_data):
    valid_procurement_data["unrecognized_field"] = "malicious_injection"
    with pytest.raises(ValidationError) as exc_info:
        ProcurementRequest(**valid_procurement_data)
    assert "Extra inputs are not permitted" in str(exc_info.value)


def test_synthetic_executor_isolation(valid_procurement_data):
    gate = ProcurementGovernanceGate()
    executor = SyntheticProcurementExecutor()
    req = ProcurementRequest(**valid_procurement_data)

    # 1. DENY case
    valid_procurement_data_deny = dict(valid_procurement_data)
    valid_procurement_data_deny["approved_vendor"] = False
    req_deny = ProcurementRequest(**valid_procurement_data_deny)
    outcome_deny = gate.evaluate_contract(GateInput(payload=req_deny, context={}))
    assert executor.execute(outcome_deny, req_deny) is False

    # 2. HALT case
    valid_procurement_data_halt = dict(valid_procurement_data)
    valid_procurement_data_halt["payment_instructions_changed"] = True
    req_halt = ProcurementRequest(**valid_procurement_data_halt)
    outcome_halt = gate.evaluate_contract(GateInput(payload=req_halt, context={}))
    assert executor.execute(outcome_halt, req_halt) is False

    # 3. INDETERMINATE case
    valid_procurement_data_indet = dict(valid_procurement_data)
    valid_procurement_data_indet["evidence_complete"] = False
    req_indet = ProcurementRequest(**valid_procurement_data_indet)
    outcome_indet = gate.evaluate_contract(GateInput(payload=req_indet, context={}))
    assert executor.execute(outcome_indet, req_indet) is False

    # 4. Explicit ALLOW case
    outcome_allow = gate.evaluate_contract(GateInput(payload=req, context={}))
    assert executor.execute(outcome_allow, req) is True

    assert len(executor.executed_orders) == 1
    assert executor.executed_orders[0]["request_id"] == "REQ-100"


def test_gate_exception_handling_and_fail_closed(valid_procurement_data):
    gate = ProcurementGovernanceGate()

    # Pass an invalid payload object type directly into evaluate_safe
    gi_invalid = GateInput(payload="not_a_valid_payload_object_or_dict", context={})
    outcome = gate.evaluate_safe(gi_invalid)

    assert outcome.decision == GateDecision.DENY
    assert outcome.passed is False
    assert "INVALID_PAYLOAD_TYPE" in outcome.reason_code


def test_audit_event_generation_and_no_sensitive_data_leakage(valid_procurement_data, tmp_path):
    log_file = str(tmp_path / "procurement_audit.jsonl")
    audit_trail = TamperEvidentAuditTrail(log_file_path=log_file)
    gate = ProcurementGovernanceGate()

    req = ProcurementRequest(**valid_procurement_data)
    outcome = gate.evaluate_contract(GateInput(payload=req, context={}))

    audit_event = AuditEvent(
        event_type=AuditLogLevel.INFO,
        gate_name=outcome.gate_name,
        reason=outcome.reason_code,
        model_id="procurement-governance-v1",
        payload_snippet=str(outcome.evidence),
    )
    audit_trail.record_event(audit_event)

    is_healthy, last_hash, err = audit_trail.inspect_log_health()
    assert is_healthy is True
    assert last_hash is not None

    with open(log_file, "r", encoding="utf-8") as f:
        log_content = f.read()

    # Verify sensitive keywords (e.g. bank account numbers, credentials) are not present
    assert "account_number" not in log_content
    assert "routing_number" not in log_content
    assert "password" not in log_content


def test_runnable_demo_executes_cleanly():
    results = run_demo()

    assert results["Scenario 1 (Compliant)"]["decision"] == "ALLOW"
    assert results["Scenario 1 (Compliant)"]["executed"] is True

    assert results["Scenario 2 (Exceeds Limit)"]["decision"] == "DENY"
    assert results["Scenario 2 (Exceeds Limit)"]["executed"] is False

    assert results["Scenario 3 (Changed Payment)"]["decision"] == "HALT"
    assert results["Scenario 3 (Changed Payment)"]["executed"] is False

    assert results["Scenario 4 (Insufficient Evidence)"]["decision"] == "INDETERMINATE"
    assert results["Scenario 4 (Insufficient Evidence)"]["executed"] is False

    assert results["Executor Total Executed"] == 1
