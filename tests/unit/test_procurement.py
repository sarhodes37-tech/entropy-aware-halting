"""
Unit tests for Procurement Governance Example Module (examples/enterprise/procurement.py).
Verifies typed inputs, deterministic governance rules, decision token HMAC binding,
trusted evidence separation, 4-way document matching, Decimal arithmetic, and execution isolation.
"""

from decimal import Decimal
import math
import threading
import time
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
    ProcurementDecisionToken,
    run_demo,
)


@pytest.fixture
def trusted_evidence():
    req = ProcurementRequest(
        request_id="REQ-100",
        purchase_order_id="PO-100",
        vendor_id="VEND-TRUSTED",
        requester_id="USR-ALICE",
        amount=Decimal("5000.00"),
        currency="USD",
        invoice_amount=Decimal("5000.00"),
        purchase_order_amount=Decimal("5000.00"),
        goods_receipt_amount=Decimal("5000.00"),
    )
    digest = req.canonical_digest()
    return TrustedEvidenceContext(
        verified_approved_vendors={"VEND-TRUSTED"},
        verified_approver_authority_limits={"USR-BOB-MANAGER": Decimal("50000.00")},
        verified_independent_approvals={f"REQ-100:{digest}:USR-BOB-MANAGER", "REQ-100:USR-BOB-MANAGER"},
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


# 1. DECISION TOKEN AUTHENTICITY TESTS
def test_untrusted_caller_forged_hmac_token_rejected_by_executor(valid_procurement_data, trusted_evidence):
    gate = ProcurementGovernanceGate(spending_limit=Decimal("10000.00"))
    executor = SyntheticProcurementExecutor()

    req = ProcurementRequest(**valid_procurement_data)
    outcome = gate.evaluate_contract(GateInput(payload=req, context={"trusted_evidence": trusted_evidence}))

    # Caller tampers with HMAC signature in the token
    forged_token_data = dict(outcome.evidence["decision_token"])
    forged_token_data["hmac_signature"] = "a" * 64
    outcome.evidence["decision_token"] = forged_token_data

    # MUST REJECT forged token
    assert executor.execute(outcome, req, gate) is False


def test_token_field_tampering_decision_or_digest_rejected_by_executor(valid_procurement_data, trusted_evidence):
    gate = ProcurementGovernanceGate(spending_limit=Decimal("10000.00"))
    executor = SyntheticProcurementExecutor()

    req = ProcurementRequest(**valid_procurement_data)
    outcome = gate.evaluate_contract(GateInput(payload=req, context={"trusted_evidence": trusted_evidence}))

    # Caller tampers with token fields without re-signing
    tampered_token = dict(outcome.evidence["decision_token"])
    tampered_token["request_digest"] = "0" * 64
    outcome.evidence["decision_token"] = tampered_token

    assert executor.execute(outcome, req, gate) is False


def test_expired_decision_token_rejected_by_executor(valid_procurement_data, trusted_evidence):
    gate = ProcurementGovernanceGate(spending_limit=Decimal("10000.00"), token_ttl_seconds=10.0)
    executor = SyntheticProcurementExecutor()

    req = ProcurementRequest(**valid_procurement_data)
    now = time.time()
    outcome = gate.evaluate_contract(GateInput(payload=req, context={"trusted_evidence": trusted_evidence}))

    # Execute at T + 20s (after expiration)
    assert executor.execute(outcome, req, gate, current_time=now + 20.0) is False


# 2. REPLAY PROTECTION & CONCURRENCY TESTS
def test_concurrent_token_execution_allows_at_most_one(valid_procurement_data, trusted_evidence):
    gate = ProcurementGovernanceGate(spending_limit=Decimal("10000.00"))
    executor = SyntheticProcurementExecutor(allow_replay=False)

    req = ProcurementRequest(**valid_procurement_data)
    outcome = gate.evaluate_contract(GateInput(payload=req, context={"trusted_evidence": trusted_evidence}))

    results = []

    def attempt_exec():
        res = executor.execute(outcome, req, gate)
        results.append(res)

    threads = [threading.Thread(target=attempt_exec) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Exactly 1 thread must succeed
    assert results.count(True) == 1
    assert results.count(False) == 9
    assert len(executor.executed_orders) == 1


# 3. 4-WAY DOCUMENT MATCHING & DISCREPANCY TESTS
def test_four_way_document_match_discrepancy(valid_procurement_data, trusted_evidence):
    gate = ProcurementGovernanceGate(match_tolerance=Decimal("0.01"))

    # PO amount differs from amount, invoice, GR
    valid_procurement_data["amount"] = Decimal("5000.00")
    valid_procurement_data["invoice_amount"] = Decimal("5000.00")
    valid_procurement_data["goods_receipt_amount"] = Decimal("5000.00")
    valid_procurement_data["purchase_order_amount"] = Decimal("5500.00")  # Discrepancy!

    req = ProcurementRequest(**valid_procurement_data)
    outcome = gate.evaluate_contract(GateInput(payload=req, context={"trusted_evidence": trusted_evidence}))

    assert outcome.decision == GateDecision.DENY
    assert outcome.reason_code == "DOCUMENT_MATCH_DISCREPANCY"


# 4. TRUSTED EVIDENCE FRESHNESS & REPLAY TESTS
def test_stale_evidence_context_returns_indeterminate(valid_procurement_data):
    gate = ProcurementGovernanceGate()
    stale_ctx = TrustedEvidenceContext(
        verified_approved_vendors={"VEND-TRUSTED"},
        evidence_complete=True,
        evidence_timestamp=time.time() - 7200.0,  # 2 hours old
        ttl_seconds=3600.0,
    )

    req = ProcurementRequest(**valid_procurement_data)
    outcome = gate.evaluate_contract(GateInput(payload=req, context={"trusted_evidence": stale_ctx}))

    assert outcome.decision == GateDecision.INDETERMINATE
    assert outcome.reason_code == "STALE_EVIDENCE_EXPIRED"


def test_evidence_replay_across_different_request_ids_denied(valid_procurement_data):
    gate = ProcurementGovernanceGate(spending_limit=Decimal("10000.00"))

    # Evidence strictly bound to REQ-100
    evidence_for_100 = TrustedEvidenceContext(
        verified_approved_vendors={"VEND-TRUSTED"},
        verified_approver_authority_limits={"USR-BOB-MANAGER": Decimal("50000.00")},
        verified_independent_approvals={"REQ-100:USR-BOB-MANAGER"},
        evidence_complete=True,
    )

    # Attempt to present this evidence for REQ-200
    valid_procurement_data["request_id"] = "REQ-200"
    valid_procurement_data["amount"] = Decimal("25000.00")
    valid_procurement_data["invoice_amount"] = Decimal("25000.00")
    valid_procurement_data["purchase_order_amount"] = Decimal("25000.00")
    valid_procurement_data["goods_receipt_amount"] = Decimal("25000.00")
    valid_procurement_data["independent_approval"] = True
    valid_procurement_data["approver_id"] = "USR-BOB-MANAGER"

    req_200 = ProcurementRequest(**valid_procurement_data)
    outcome = gate.evaluate_contract(GateInput(payload=req_200, context={"trusted_evidence": evidence_for_100}))

    assert outcome.decision == GateDecision.DENY
    assert outcome.reason_code == "UNVERIFIED_INDEPENDENT_APPROVAL_RECORD"


# ADDITIONAL EDGE & BOUNDARY TESTS
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


@pytest.mark.parametrize("bad_threshold", [True, False, "invalid_string", -100.0, float("nan"), float("inf")])
def test_gate_threshold_configuration_validation(bad_threshold):
    with pytest.raises(ValueError):
        ProcurementGovernanceGate(spending_limit=bad_threshold)


def test_segregation_of_duties_violation(valid_procurement_data, trusted_evidence):
    gate = ProcurementGovernanceGate(spending_limit=Decimal("10000.00"))
    valid_procurement_data["amount"] = Decimal("50000.00")
    valid_procurement_data["invoice_amount"] = Decimal("50000.00")
    valid_procurement_data["purchase_order_amount"] = Decimal("50000.00")
    valid_procurement_data["goods_receipt_amount"] = Decimal("50000.00")
    valid_procurement_data["independent_approval"] = True
    valid_procurement_data["approver_id"] = "USR-ALICE"  # Self-approval!

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
