"""
Unit tests for Procurement Governance Example Module (examples/enterprise/procurement.py).
Verifies typed inputs, deterministic governance rules, decision token binding,
trusted evidence separation, authoritative amount limits, Decimal arithmetic, and execution isolation.
"""

from decimal import Decimal
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
    TrustedEvidenceContext,
    ProcurementGovernanceGate,
    SyntheticProcurementExecutor,
    run_demo,
)


@pytest.fixture
def trusted_evidence():
    return TrustedEvidenceContext(
        verified_approved_vendors={"VEND-TRUSTED"},
        verified_approver_authority_limits={"USR-BOB-MANAGER": Decimal("50000.00")},
        verified_independent_approvals={"REQ-100:USR-BOB-MANAGER"},
        evidence_complete=True,
    )


@pytest.fixture
def valid_procurement_data():
    return {
        "request_id": "REQ-100",
        "purchase_order_id": "PO-100",
        "vendor_id": "VEND-TRUSTED",
        "requester_id": "USR-ALICE",
        "amount": Decimal("5000.00"),
        "currency": "USD",
        "invoice_amount": Decimal("5000.00"),
        "purchase_order_amount": Decimal("5000.00"),
        "goods_receipt_amount": Decimal("5000.00"),
        "payment_instructions_changed": False,
        "independent_approval": False,
        "approver_id": None,
    }


def test_compliant_request_returns_allow(valid_procurement_data, trusted_evidence):
    gate = ProcurementGovernanceGate(spending_limit=Decimal("10000.00"))
    req = ProcurementRequest(**valid_procurement_data)
    gi = GateInput(payload=req, context={"trusted_evidence": trusted_evidence})

    outcome = gate.evaluate_contract(gi)

    assert outcome.decision == GateDecision.ALLOW
    assert outcome.passed is True
    assert outcome.reason_code == "PROCUREMENT_APPROVAL_GRANTED"
    assert outcome.evidence["request_id"] == "REQ-100"


# FINDING 1 TESTS: Decision Binding and Cross-Request Prevention
def test_finding_1_decision_binding_prevents_cross_request_execution(valid_procurement_data, trusted_evidence):
    gate = ProcurementGovernanceGate(spending_limit=Decimal("10000.00"))
    executor = SyntheticProcurementExecutor()

    req_a = ProcurementRequest(**valid_procurement_data)
    outcome_a = gate.evaluate_contract(GateInput(payload=req_a, context={"trusted_evidence": trusted_evidence}))

    # Create request B
    data_b = dict(valid_procurement_data)
    data_b["request_id"] = "REQ-999-OTHER"
    req_b = ProcurementRequest(**data_b)

    # Attempt to execute ALLOW for A against request B: MUST REJECT
    assert executor.execute(outcome_a, req_b, gate) is False
    assert len(executor.executed_orders) == 0


def test_finding_1_mutation_after_evaluation_invalidates_decision(valid_procurement_data, trusted_evidence):
    gate = ProcurementGovernanceGate(spending_limit=Decimal("10000.00"))
    executor = SyntheticProcurementExecutor()

    req = ProcurementRequest(**valid_procurement_data)
    outcome = gate.evaluate_contract(GateInput(payload=req, context={"trusted_evidence": trusted_evidence}))

    # Mutate request after evaluation (e.g. increase amount)
    mutated_data = dict(valid_procurement_data)
    mutated_data["amount"] = Decimal("999999.00")
    mutated_req = ProcurementRequest(**mutated_data)

    assert executor.execute(outcome, mutated_req, gate) is False


def test_finding_1_policy_change_invalidates_decision_token(valid_procurement_data, trusted_evidence):
    gate_v1 = ProcurementGovernanceGate(spending_limit=Decimal("10000.00"))
    executor = SyntheticProcurementExecutor()

    req = ProcurementRequest(**valid_procurement_data)
    outcome = gate_v1.evaluate_contract(GateInput(payload=req, context={"trusted_evidence": trusted_evidence}))

    # Policy updated/reconfigured
    gate_v2 = ProcurementGovernanceGate(spending_limit=Decimal("2000.00"))

    assert executor.execute(outcome, req, gate_v2) is False


def test_finding_1_replay_prevention_rejects_reused_decision_token(valid_procurement_data, trusted_evidence):
    gate = ProcurementGovernanceGate(spending_limit=Decimal("10000.00"))
    executor = SyntheticProcurementExecutor(allow_replay=False)

    req = ProcurementRequest(**valid_procurement_data)
    outcome = gate.evaluate_contract(GateInput(payload=req, context={"trusted_evidence": trusted_evidence}))

    # First execution succeeds
    assert executor.execute(outcome, req, gate) is True
    # Replay attempt MUST REJECT
    assert executor.execute(outcome, req, gate) is False


# FINDING 2 TESTS: Untrusted Caller Assertions vs Trusted Evidence
def test_finding_2_caller_asserted_vendor_status_without_trusted_evidence_fails_closed(valid_procurement_data):
    gate = ProcurementGovernanceGate()
    valid_procurement_data["caller_asserted_vendor_approved"] = True
    req = ProcurementRequest(**valid_procurement_data)

    # Empty/Untrusted evidence context
    empty_ctx = TrustedEvidenceContext(verified_approved_vendors=set())
    outcome = gate.evaluate_contract(GateInput(payload=req, context={"trusted_evidence": empty_ctx}))

    assert outcome.decision == GateDecision.DENY
    assert outcome.reason_code == "UNAPPROVED_VENDOR"


def test_finding_2_unverified_independent_approval_record_fails_closed(valid_procurement_data, trusted_evidence):
    gate = ProcurementGovernanceGate(spending_limit=Decimal("10000.00"))
    valid_procurement_data["amount"] = Decimal("25000.00")
    valid_procurement_data["invoice_amount"] = Decimal("25000.00")
    valid_procurement_data["purchase_order_amount"] = Decimal("25000.00")
    valid_procurement_data["goods_receipt_amount"] = Decimal("25000.00")
    valid_procurement_data["independent_approval"] = True
    valid_procurement_data["approver_id"] = "USR-BOB-MANAGER"

    # Context missing the approval attestation for REQ-100
    unattested_ctx = TrustedEvidenceContext(
        verified_approved_vendors={"VEND-TRUSTED"},
        verified_approver_authority_limits={"USR-BOB-MANAGER": Decimal("50000.00")},
        verified_independent_approvals=set(),  # Missing!
        evidence_complete=True,
    )

    req = ProcurementRequest(**valid_procurement_data)
    outcome = gate.evaluate_contract(GateInput(payload=req, context={"trusted_evidence": unattested_ctx}))

    assert outcome.decision == GateDecision.DENY
    assert outcome.reason_code == "UNVERIFIED_INDEPENDENT_APPROVAL_RECORD"


def test_finding_2_insufficient_approver_authority_limit(valid_procurement_data):
    gate = ProcurementGovernanceGate(spending_limit=Decimal("10000.00"))
    valid_procurement_data["amount"] = Decimal("80000.00")
    valid_procurement_data["invoice_amount"] = Decimal("80000.00")
    valid_procurement_data["purchase_order_amount"] = Decimal("80000.00")
    valid_procurement_data["goods_receipt_amount"] = Decimal("80000.00")
    valid_procurement_data["independent_approval"] = True
    valid_procurement_data["approver_id"] = "USR-BOB-MANAGER"

    # Approver limit is 50,000, but request is 80,000
    low_limit_ctx = TrustedEvidenceContext(
        verified_approved_vendors={"VEND-TRUSTED"},
        verified_approver_authority_limits={"USR-BOB-MANAGER": Decimal("50000.00")},
        verified_independent_approvals={"REQ-100:USR-BOB-MANAGER"},
        evidence_complete=True,
    )

    req = ProcurementRequest(**valid_procurement_data)
    outcome = gate.evaluate_contract(GateInput(payload=req, context={"trusted_evidence": low_limit_ctx}))

    assert outcome.decision == GateDecision.DENY
    assert outcome.reason_code == "INSUFFICIENT_APPROVER_AUTHORITY_LIMIT"


# FINDING 3 TESTS: Authoritative Transaction Amount & Spending Limit Consistency
def test_finding_3_artificially_low_amount_field_cannot_bypass_spending_limit(valid_procurement_data, trusted_evidence):
    gate = ProcurementGovernanceGate(spending_limit=Decimal("10000.00"))

    # Caller sets "amount" = 500.00, but invoice/PO amounts are 25,000.00!
    valid_procurement_data["amount"] = Decimal("500.00")
    valid_procurement_data["invoice_amount"] = Decimal("25000.00")
    valid_procurement_data["purchase_order_amount"] = Decimal("25000.00")
    valid_procurement_data["goods_receipt_amount"] = Decimal("25000.00")

    req = ProcurementRequest(**valid_procurement_data)
    outcome = gate.evaluate_contract(GateInput(payload=req, context={"trusted_evidence": trusted_evidence}))

    # MUST DENY because authoritative amount is max(500, 25000) = 25000 > 10000
    assert outcome.decision == GateDecision.DENY
    assert outcome.reason_code == "EXCEEDS_SPENDING_AUTHORITY"


def test_spending_authority_limit_exact_boundary(valid_procurement_data, trusted_evidence):
    gate = ProcurementGovernanceGate(spending_limit=Decimal("10000.00"))

    # Exactly at boundary: ALLOW
    valid_procurement_data["amount"] = Decimal("10000.00")
    valid_procurement_data["invoice_amount"] = Decimal("10000.00")
    valid_procurement_data["purchase_order_amount"] = Decimal("10000.00")
    valid_procurement_data["goods_receipt_amount"] = Decimal("10000.00")
    req_at_limit = ProcurementRequest(**valid_procurement_data)
    outcome_at_limit = gate.evaluate_contract(GateInput(payload=req_at_limit, context={"trusted_evidence": trusted_evidence}))

    assert outcome_at_limit.decision == GateDecision.ALLOW

    # Just above boundary: DENY
    valid_procurement_data["amount"] = Decimal("10000.01")
    valid_procurement_data["invoice_amount"] = Decimal("10000.01")
    valid_procurement_data["purchase_order_amount"] = Decimal("10000.01")
    valid_procurement_data["goods_receipt_amount"] = Decimal("10000.01")
    req_above_limit = ProcurementRequest(**valid_procurement_data)
    outcome_above_limit = gate.evaluate_contract(GateInput(payload=req_above_limit, context={"trusted_evidence": trusted_evidence}))

    assert outcome_above_limit.decision == GateDecision.DENY
    assert outcome_above_limit.reason_code == "EXCEEDS_SPENDING_AUTHORITY"


# FINDING 4 TESTS: Gate Threshold Validation & Decimal Financial Arithmetic
@pytest.mark.parametrize("bad_threshold", [True, False, "invalid_string", -100.0, float("nan"), float("inf")])
def test_finding_4_gate_threshold_configuration_validation(bad_threshold):
    with pytest.raises(ValueError):
        ProcurementGovernanceGate(spending_limit=bad_threshold)


def test_finding_4_three_way_match_exact_decimal_precision(valid_procurement_data, trusted_evidence):
    gate = ProcurementGovernanceGate(match_tolerance=Decimal("0.01"))

    # Discrepancy within tolerance (0.005 <= 0.01)
    valid_procurement_data["invoice_amount"] = Decimal("5000.005")
    req_within = ProcurementRequest(**valid_procurement_data)
    outcome_within = gate.evaluate_contract(GateInput(payload=req_within, context={"trusted_evidence": trusted_evidence}))
    assert outcome_within.decision == GateDecision.ALLOW

    # Discrepancy exceeding tolerance (0.0101 > 0.01)
    valid_procurement_data["invoice_amount"] = Decimal("5000.0101")
    req_exceeded = ProcurementRequest(**valid_procurement_data)
    outcome_exceeded = gate.evaluate_contract(GateInput(payload=req_exceeded, context={"trusted_evidence": trusted_evidence}))
    assert outcome_exceeded.decision == GateDecision.DENY
    assert outcome_exceeded.reason_code == "THREE_WAY_MATCH_DISCREPANCY"


def test_segregation_of_duties_violation(valid_procurement_data, trusted_evidence):
    gate = ProcurementGovernanceGate(spending_limit=Decimal("10000.00"))
    valid_procurement_data["amount"] = Decimal("50000.00")
    valid_procurement_data["invoice_amount"] = Decimal("50000.00")
    valid_procurement_data["purchase_order_amount"] = Decimal("50000.00")
    valid_procurement_data["goods_receipt_amount"] = Decimal("50000.00")
    valid_procurement_data["independent_approval"] = True
    valid_procurement_data["approver_id"] = "USR-ALICE"  # Self-approval attempt!

    req = ProcurementRequest(**valid_procurement_data)
    outcome = gate.evaluate_contract(GateInput(payload=req, context={"trusted_evidence": trusted_evidence}))

    assert outcome.decision == GateDecision.DENY
    assert outcome.reason_code == "SEGREGATION_OF_DUTIES_VIOLATION"


def test_payment_instruction_change_triggers_halt(valid_procurement_data, trusted_evidence):
    valid_procurement_data["payment_instructions_changed"] = True
    gate = ProcurementGovernanceGate()
    req = ProcurementRequest(**valid_procurement_data)

    outcome = gate.evaluate_contract(GateInput(payload=req, context={"trusted_evidence": trusted_evidence}))

    assert outcome.decision == GateDecision.HALT
    assert outcome.passed is False
    assert outcome.reason_code == "PAYMENT_INSTRUCTION_CHANGE_HOLD"


def test_incomplete_evidence_returns_indeterminate(valid_procurement_data):
    gate = ProcurementGovernanceGate()
    incomplete_ctx = TrustedEvidenceContext(evidence_complete=False)

    req = ProcurementRequest(**valid_procurement_data)
    outcome = gate.evaluate_contract(GateInput(payload=req, context={"trusted_evidence": incomplete_ctx}))

    assert outcome.decision == GateDecision.INDETERMINATE
    assert outcome.reason_code == "INCOMPLETE_OR_UNTRUSTED_EVIDENCE"


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


def test_audit_event_generation_and_no_sensitive_data_leakage(valid_procurement_data, trusted_evidence, tmp_path):
    log_file = str(tmp_path / "procurement_audit.jsonl")
    audit_trail = TamperEvidentAuditTrail(log_file_path=log_file)
    gate = ProcurementGovernanceGate()

    req = ProcurementRequest(**valid_procurement_data)
    outcome = gate.evaluate_contract(GateInput(payload=req, context={"trusted_evidence": trusted_evidence}))

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
