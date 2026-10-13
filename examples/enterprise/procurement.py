"""
Procurement Governance Example Module (examples/enterprise/procurement.py).

Demonstrates how EpistemicOS governs purchase-order approval in enterprise procurement
through typed inputs, deterministic policy checks, explicit decision semantics,
least-privilege authorization, and auditable outcomes.

Purpose & Policy Assumptions:
- Evaluates purchase orders against organization policy (vendor eligibility, spending limits,
  segregation of duties, 3-way matching, payment instruction security, evidence completeness).
- Configurable demonstration thresholds (e.g. $10,000 spending limit, $0.01 3-way match tolerance).
- Operates strictly as a pre-execution governance layer. Does not execute payments, modify
  bank details, or interface with external financial clearing systems.

Decision Taxonomy:
- ALLOW: All mandatory checks pass and valid trusted evidence is present.
- DENY: Explicit policy violation makes the request ineligible (unapproved vendor, limit exceeded,
  segregation of duties failure, 3-way match mismatch).
- HALT: Execution stopped due to a security-sensitive condition requiring manual out-of-band hold
  (e.g., changed payment instructions).
- INDETERMINATE: Required evidence is incomplete, missing, or contradictory.

Trusted Evidence Boundary:
- System-verified flags (e.g., vendor registration status from trusted ERP, verified goods receipt)
  are distinguished from user-supplied assertions. Unvalidated dictionaries or arbitrary objects are rejected.

Governance Demonstration Disclaimer:
- This module is a reference governance demonstration for EpistemicOS and does not constitute
  a production payment or procurement engine.
"""

import math
import time
from typing import Dict, Any, Optional, List

from pydantic import BaseModel, ConfigDict, Field, field_validator

from epistemicos.gates import (
    ControlPlaneGate,
    GateConfig,
    GateDecision,
    GateInput,
    GateOutcome,
    GateAction,
    GateResult,
)


class ProcurementRequest(BaseModel):
    """
    Synthetic purchase-order request with strict validation and explicit evidence boundary.
    Rejects malformed types, non-finite or negative amounts, and unexpected fields.
    """

    model_config = ConfigDict(extra="forbid", validate_default=True)

    request_id: str = Field(min_length=1, max_length=128)
    purchase_order_id: str = Field(min_length=1, max_length=128)
    vendor_id: str = Field(min_length=1, max_length=128)
    requester_id: str = Field(min_length=1, max_length=128)

    amount: float
    currency: str

    invoice_amount: float
    purchase_order_amount: float
    goods_receipt_amount: float

    payment_instructions_changed: bool = False

    approved_vendor: Optional[bool] = None  # Trusted system evidence
    independent_approval: bool = False
    approver_id: Optional[str] = None

    evidence_complete: bool = True
    evidence_provenance: Dict[str, str] = Field(default_factory=dict)

    @field_validator(
        "amount",
        "invoice_amount",
        "purchase_order_amount",
        "goods_receipt_amount",
        mode="before",
    )
    @classmethod
    def validate_numeric_amount(cls, value: Any) -> float:
        if isinstance(value, bool):
            raise ValueError("Booleans masquerading as numeric amounts are strictly forbidden")
        if not isinstance(value, (int, float)):
            raise ValueError("Amount must be a numeric float or int")
        val = float(value)
        if not math.isfinite(val):
            raise ValueError("Amount must be finite")
        if val <= 0:
            raise ValueError("Amount must be strictly positive")
        return val

    @field_validator("request_id", "purchase_order_id", "vendor_id", "requester_id")
    @classmethod
    def validate_identifiers(cls, value: str) -> str:
        if not isinstance(value, str):
            raise ValueError("Identifier must be a string")
        stripped = value.strip()
        if not stripped:
            raise ValueError("Identifier must not be blank")
        return stripped

    @field_validator("approver_id")
    @classmethod
    def validate_approver_id(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("Approver ID must be a string")
        stripped = value.strip()
        if not stripped:
            raise ValueError("Approver ID must not be blank")
        return stripped

    @field_validator("currency")
    @classmethod
    def validate_currency(cls, value: str) -> str:
        if not isinstance(value, str):
            raise ValueError("Currency must be a string")
        allowed = {"USD", "EUR", "GBP", "CAD", "AUD", "JPY"}
        val = value.strip().upper()
        if val not in allowed:
            raise ValueError(f"Unsupported currency: '{value}'")
        return val


class ProcurementGovernanceGate(ControlPlaneGate):
    """
    Deterministic control-plane gate for procurement purchase-order governance.
    Enforces spending authority, vendor status, segregation of duties, 3-way match,
    payment modification holds, and evidence integrity.
    """

    def __init__(
        self,
        spending_limit: float = 10000.0,
        match_tolerance: float = 0.01,
        config: Optional[GateConfig] = None,
    ):
        super().__init__(config=config or GateConfig(version="1.0.0", is_critical=True))
        self.spending_limit = spending_limit
        self.match_tolerance = match_tolerance

    def _parse_and_validate_request(
        self, payload: Any, t0: float
    ) -> tuple[Optional[ProcurementRequest], Optional[GateOutcome]]:
        if isinstance(payload, ProcurementRequest):
            return payload, None
        elif isinstance(payload, dict):
            try:
                req = ProcurementRequest.model_validate(payload)
                return req, None
            except Exception as e:
                return None, GateOutcome(
                    decision=GateDecision.DENY,
                    reason_code=f"MALFORMED_PROCUREMENT_REQUEST: {str(e)}",
                    gate_name=self.gate_name,
                    gate_version=self.config.version,
                    evidence={"error": str(e), "exception_type": type(e).__name__},
                    latency_ms=(time.perf_counter() - t0) * 1000.0,
                )
        else:
            return None, GateOutcome(
                decision=GateDecision.DENY,
                reason_code="INVALID_PAYLOAD_TYPE: Expected ProcurementRequest or dict",
                gate_name=self.gate_name,
                gate_version=self.config.version,
                evidence={"provided_type": type(payload).__name__},
                latency_ms=(time.perf_counter() - t0) * 1000.0,
            )

    def evaluate_contract(self, gate_input: GateInput) -> GateOutcome:
        t0 = time.perf_counter()
        req, err_outcome = self._parse_and_validate_request(gate_input.payload, t0)
        if err_outcome:
            return err_outcome
        assert req is not None

        # Rule 6: Incomplete or contradictory evidence
        if not req.evidence_complete:
            return GateOutcome(
                decision=GateDecision.INDETERMINATE,
                reason_code="INCOMPLETE_EVIDENCE",
                gate_name=self.gate_name,
                gate_version=self.config.version,
                evidence={"request_id": req.request_id, "evidence_complete": False},
                latency_ms=(time.perf_counter() - t0) * 1000.0,
            )

        if req.approved_vendor is None:
            return GateOutcome(
                decision=GateDecision.INDETERMINATE,
                reason_code="UNVERIFIABLE_VENDOR_STATUS",
                gate_name=self.gate_name,
                gate_version=self.config.version,
                evidence={"request_id": req.request_id, "vendor_id": req.vendor_id},
                latency_ms=(time.perf_counter() - t0) * 1000.0,
            )

        if req.independent_approval and not req.approver_id:
            return GateOutcome(
                decision=GateDecision.INDETERMINATE,
                reason_code="CONTRADICTORY_APPROVAL_EVIDENCE",
                gate_name=self.gate_name,
                gate_version=self.config.version,
                evidence={"independent_approval": True, "approver_id": None},
                latency_ms=(time.perf_counter() - t0) * 1000.0,
            )

        # Rule 1: Vendor eligibility
        if req.approved_vendor is False:
            return GateOutcome(
                decision=GateDecision.DENY,
                reason_code="UNAPPROVED_VENDOR",
                gate_name=self.gate_name,
                gate_version=self.config.version,
                evidence={"vendor_id": req.vendor_id, "approved_vendor": False},
                latency_ms=(time.perf_counter() - t0) * 1000.0,
            )

        # Rule 5: Payment-instruction changes trigger security hold
        if req.payment_instructions_changed:
            return GateOutcome(
                decision=GateDecision.HALT,
                reason_code="PAYMENT_INSTRUCTION_CHANGE_HOLD",
                gate_name=self.gate_name,
                gate_version=self.config.version,
                evidence={"request_id": req.request_id, "vendor_id": req.vendor_id},
                latency_ms=(time.perf_counter() - t0) * 1000.0,
            )

        # Rule 4: Three-way match
        po_diff = abs(req.invoice_amount - req.purchase_order_amount)
        gr_diff = abs(req.invoice_amount - req.goods_receipt_amount)
        po_gr_diff = abs(req.purchase_order_amount - req.goods_receipt_amount)
        max_discrepancy = max(po_diff, gr_diff, po_gr_diff)

        if max_discrepancy > self.match_tolerance:
            return GateOutcome(
                decision=GateDecision.DENY,
                reason_code="THREE_WAY_MATCH_DISCREPANCY",
                gate_name=self.gate_name,
                gate_version=self.config.version,
                evidence={
                    "max_discrepancy": round(max_discrepancy, 4),
                    "tolerance": self.match_tolerance,
                    "invoice_amount": req.invoice_amount,
                    "po_amount": req.purchase_order_amount,
                    "gr_amount": req.goods_receipt_amount,
                },
                latency_ms=(time.perf_counter() - t0) * 1000.0,
            )

        # Rule 3: Segregation of duties
        if req.independent_approval and req.approver_id == req.requester_id:
            return GateOutcome(
                decision=GateDecision.DENY,
                reason_code="SEGREGATION_OF_DUTIES_VIOLATION",
                gate_name=self.gate_name,
                gate_version=self.config.version,
                evidence={
                    "requester_id": req.requester_id,
                    "approver_id": req.approver_id,
                },
                latency_ms=(time.perf_counter() - t0) * 1000.0,
            )

        # Rule 2: Spending authority
        if req.amount > self.spending_limit:
            if not req.independent_approval:
                return GateOutcome(
                    decision=GateDecision.DENY,
                    reason_code="EXCEEDS_SPENDING_AUTHORITY",
                    gate_name=self.gate_name,
                    gate_version=self.config.version,
                    evidence={
                        "amount": req.amount,
                        "spending_limit": self.spending_limit,
                        "currency": req.currency,
                    },
                    latency_ms=(time.perf_counter() - t0) * 1000.0,
                )

        # Rule 7: Successful approval
        return GateOutcome(
            decision=GateDecision.ALLOW,
            reason_code="PROCUREMENT_APPROVAL_GRANTED",
            gate_name=self.gate_name,
            gate_version=self.config.version,
            evidence={
                "request_id": req.request_id,
                "amount": req.amount,
                "currency": req.currency,
                "vendor_id": req.vendor_id,
            },
            latency_ms=(time.perf_counter() - t0) * 1000.0,
        )


class SyntheticProcurementExecutor:
    """
    Downstream synthetic action boundary test double.
    Records purchase order executions strictly when governed by an explicit ALLOW decision.
    """

    def __init__(self):
        self.executed_orders: List[Dict[str, Any]] = []

    def execute(self, outcome: Any, request: ProcurementRequest) -> bool:
        decision = getattr(outcome, "decision", None)
        passed = getattr(outcome, "passed", False)

        if decision != GateDecision.ALLOW or not passed:
            return False

        self.executed_orders.append({
            "request_id": request.request_id,
            "purchase_order_id": request.purchase_order_id,
            "vendor_id": request.vendor_id,
            "amount": request.amount,
            "currency": request.currency,
            "timestamp": time.time(),
        })
        return True


def run_demo() -> Dict[str, Any]:
    """Runs a synthetic procurement governance demonstration across 4 scenarios."""
    gate = ProcurementGovernanceGate(spending_limit=10000.0)
    executor = SyntheticProcurementExecutor()

    # Scenario 1: Compliant Request
    compliant_req = ProcurementRequest(
        request_id="REQ-001",
        purchase_order_id="PO-1001",
        vendor_id="VEND-ACME",
        requester_id="USR-ALICE",
        amount=5000.0,
        currency="USD",
        invoice_amount=5000.0,
        purchase_order_amount=5000.0,
        goods_receipt_amount=5000.0,
        approved_vendor=True,
    )
    outcome_1 = gate.evaluate_contract(GateInput(payload=compliant_req, context={}))
    exec_1 = executor.execute(outcome_1, compliant_req)

    # Scenario 2: Exceeding Spending Authority (Without valid independent approval)
    over_limit_req = ProcurementRequest(
        request_id="REQ-002",
        purchase_order_id="PO-1002",
        vendor_id="VEND-ACME",
        requester_id="USR-BOB",
        amount=25000.0,
        currency="USD",
        invoice_amount=25000.0,
        purchase_order_amount=25000.0,
        goods_receipt_amount=25000.0,
        approved_vendor=True,
    )
    outcome_2 = gate.evaluate_contract(GateInput(payload=over_limit_req, context={}))
    exec_2 = executor.execute(outcome_2, over_limit_req)

    # Scenario 3: Payment Instructions Changed
    changed_payment_req = ProcurementRequest(
        request_id="REQ-003",
        purchase_order_id="PO-1003",
        vendor_id="VEND-ACME",
        requester_id="USR-CHARLIE",
        amount=3000.0,
        currency="USD",
        invoice_amount=3000.0,
        purchase_order_amount=3000.0,
        goods_receipt_amount=3000.0,
        approved_vendor=True,
        payment_instructions_changed=True,
    )
    outcome_3 = gate.evaluate_contract(GateInput(payload=changed_payment_req, context={}))
    exec_3 = executor.execute(outcome_3, changed_payment_req)

    # Scenario 4: Insufficient Evidence
    incomplete_req = ProcurementRequest(
        request_id="REQ-004",
        purchase_order_id="PO-1004",
        vendor_id="VEND-UNKNOWN",
        requester_id="USR-DAVE",
        amount=1200.0,
        currency="USD",
        invoice_amount=1200.0,
        purchase_order_amount=1200.0,
        goods_receipt_amount=1200.0,
        approved_vendor=None,  # Missing trusted vendor status
        evidence_complete=False,
    )
    outcome_4 = gate.evaluate_contract(GateInput(payload=incomplete_req, context={}))
    exec_4 = executor.execute(outcome_4, incomplete_req)

    results = {
        "Scenario 1 (Compliant)": {
            "decision": outcome_1.decision.value,
            "reason": outcome_1.reason_code,
            "executed": exec_1,
        },
        "Scenario 2 (Exceeds Limit)": {
            "decision": outcome_2.decision.value,
            "reason": outcome_2.reason_code,
            "executed": exec_2,
        },
        "Scenario 3 (Changed Payment)": {
            "decision": outcome_3.decision.value,
            "reason": outcome_3.reason_code,
            "executed": exec_3,
        },
        "Scenario 4 (Insufficient Evidence)": {
            "decision": outcome_4.decision.value,
            "reason": outcome_4.reason_code,
            "executed": exec_4,
        },
        "Executor Total Executed": len(executor.executed_orders),
    }
    return results


if __name__ == "__main__":
    demo_results = run_demo()
    print("=== EpistemicOS Procurement Governance Demonstration ===")
    for scenario, data in demo_results.items():
        if scenario == "Executor Total Executed":
            print(f"\nTotal Executed Orders in Synthetic Executor: {data}")
        else:
            print(f"\n{scenario}:")
            print(f"  Decision: {data['decision']}")
            print(f"  Reason:   {data['reason']}")
            print(f"  Executed: {data['executed']}")
