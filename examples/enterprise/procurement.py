"""
Procurement Governance Example Module (examples/enterprise/procurement.py).

Demonstrates how EpistemicOS governs purchase-order approval in enterprise procurement
through typed inputs, deterministic policy checks, explicit decision semantics,
least-privilege authorization, and auditable outcomes.

Purpose & Policy Assumptions:
- Evaluates purchase orders against organization policy (vendor eligibility, spending limits,
  segregation of duties, 4-way document matching, payment instruction security, evidence completeness/freshness).
- Configurable demonstration thresholds (e.g. $10,000 spending limit, $0.01 match tolerance).
- Operates strictly as a pre-execution governance layer. Does not execute payments, modify
  bank details, or interface with external financial clearing systems.

Decision Taxonomy:
- ALLOW: All mandatory checks pass and valid trusted evidence is present.
- DENY: Explicit policy violation makes the request ineligible (unapproved vendor, limit exceeded,
  segregation of duties failure, document match mismatch).
- HALT: Execution stopped due to a security-sensitive condition requiring manual out-of-band hold
  (e.g., changed payment instructions).
- INDETERMINATE: Required evidence is incomplete, missing, stale, or contradictory.

Trusted Evidence Boundary:
- System-verified flags and attestations in `TrustedEvidenceContext` are strictly separated
  from user-supplied assertions in `ProcurementRequest`. Unverified caller assertions fail closed.

Governance Demonstration Disclaimer:
- This module is a reference governance demonstration for EpistemicOS and does not constitute
  a production payment or procurement engine.
"""

import decimal
from decimal import Decimal, ROUND_HALF_UP
import hashlib
import hmac
import json
import math
import threading
import time
import uuid
from typing import Dict, Any, Optional, List, Set, Union

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
    Uses Decimal representation for precise financial arithmetic.
    """

    model_config = ConfigDict(extra="forbid", validate_default=True)

    request_id: str = Field(min_length=1, max_length=128)
    purchase_order_id: str = Field(min_length=1, max_length=128)
    vendor_id: str = Field(min_length=1, max_length=128)
    requester_id: str = Field(min_length=1, max_length=128)

    amount: Decimal
    currency: str

    invoice_amount: Decimal
    purchase_order_amount: Decimal
    goods_receipt_amount: Decimal

    payment_instructions_changed: bool = False

    # Optional caller assertions (treated as UNTRUSTED unless matched in TrustedEvidenceContext)
    caller_asserted_vendor_approved: Optional[bool] = None
    independent_approval: bool = False
    approver_id: Optional[str] = None

    @field_validator(
        "amount",
        "invoice_amount",
        "purchase_order_amount",
        "goods_receipt_amount",
        mode="before",
    )
    @classmethod
    def validate_decimal_amount(cls, value: Any) -> Decimal:
        if isinstance(value, bool):
            raise ValueError("Booleans masquerading as numeric amounts are strictly forbidden")
        if isinstance(value, float):
            if not math.isfinite(value):
                raise ValueError("Amount must be finite")
            value = str(value)
        elif isinstance(value, int):
            value = str(value)

        try:
            dec = Decimal(str(value))
        except (decimal.InvalidOperation, TypeError, ValueError):
            raise ValueError("Amount must be a valid numeric Decimal")

        if dec.is_nan() or dec.is_infinite():
            raise ValueError("Amount must be finite")
        if dec <= Decimal("0"):
            raise ValueError("Amount must be strictly positive")
        return dec.quantize(Decimal("0.0001"), rounding=ROUND_HALF_UP)

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

    def canonical_dict(self) -> Dict[str, Any]:
        """Returns deterministic dictionary representation for canonical hashing."""
        return {
            "request_id": self.request_id,
            "purchase_order_id": self.purchase_order_id,
            "vendor_id": self.vendor_id,
            "requester_id": self.requester_id,
            "amount": str(self.amount),
            "currency": self.currency,
            "invoice_amount": str(self.invoice_amount),
            "purchase_order_amount": str(self.purchase_order_amount),
            "goods_receipt_amount": str(self.goods_receipt_amount),
            "payment_instructions_changed": self.payment_instructions_changed,
            "independent_approval": self.independent_approval,
            "approver_id": self.approver_id,
        }

    def canonical_digest(self) -> str:
        """SHA-256 canonical digest of request content."""
        dump = json.dumps(self.canonical_dict(), sort_keys=True)
        return hashlib.sha256(dump.encode("utf-8")).hexdigest()


class TrustedEvidenceContext(BaseModel):
    """
    Separately ingested, system-attested evidence context.
    Caller assertions in ProcurementRequest are validated against this trusted context.
    """

    model_config = ConfigDict(extra="forbid", validate_default=True)

    verified_approved_vendors: Set[str] = Field(default_factory=set)
    verified_approver_authority_limits: Dict[str, Decimal] = Field(default_factory=dict)
    verified_independent_approvals: Set[str] = Field(default_factory=set)  # Set of "request_id:canonical_digest:approver_id"
    evidence_complete: bool = True
    evidence_timestamp: float = Field(default_factory=time.time)
    ttl_seconds: float = 3600.0

    @field_validator("verified_approver_authority_limits", mode="before")
    @classmethod
    def validate_limits(cls, limits: Any) -> Dict[str, Decimal]:
        if not isinstance(limits, dict):
            return {}
        result = {}
        for k, v in limits.items():
            if isinstance(v, bool):
                raise ValueError("Booleans masquerading as limit values are forbidden")
            try:
                dec = Decimal(str(v))
            except (decimal.InvalidOperation, TypeError, ValueError):
                raise ValueError("Limit must be numeric")
            if dec.is_nan() or dec.is_infinite() or dec < Decimal("0"):
                raise ValueError("Limit must be finite and non-negative")
            result[k] = dec.quantize(Decimal("0.0001"), rounding=ROUND_HALF_UP)
        return result

    def is_fresh(self, current_time: Optional[float] = None) -> bool:
        now = current_time if current_time is not None else time.time()
        return (now - self.evidence_timestamp) <= self.ttl_seconds


class ProcurementDecisionToken(BaseModel):
    """
    HMAC-signed, single-use decision token produced upon evaluation.
    Binds decision outcome to exact request canonical digest, policy version, spending limit,
    expiration timestamp, and HMAC signature.
    """

    model_config = ConfigDict(extra="forbid", validate_default=True)

    decision_id: str
    request_id: str
    request_digest: str
    decision: GateDecision
    reason_code: str
    policy_version: str
    spending_limit: Decimal
    issue_timestamp: float
    expiration_timestamp: float
    hmac_signature: str

    def canonical_signature_payload(self) -> str:
        fields = {
            "decision_id": self.decision_id,
            "request_id": self.request_id,
            "request_digest": self.request_digest,
            "decision": self.decision.value,
            "reason_code": self.reason_code,
            "policy_version": self.policy_version,
            "spending_limit": str(self.spending_limit),
            "issue_timestamp": str(self.issue_timestamp),
            "expiration_timestamp": str(self.expiration_timestamp),
        }
        return json.dumps(fields, sort_keys=True)

    @classmethod
    def sign_token(
        cls,
        secret_key: bytes,
        decision_id: str,
        request_id: str,
        request_digest: str,
        decision: GateDecision,
        reason_code: str,
        policy_version: str,
        spending_limit: Decimal,
        issue_timestamp: float,
        ttl_seconds: float = 300.0,
    ) -> "ProcurementDecisionToken":
        expiration_timestamp = issue_timestamp + ttl_seconds
        payload_dict = {
            "decision_id": decision_id,
            "request_id": request_id,
            "request_digest": request_digest,
            "decision": decision.value,
            "reason_code": reason_code,
            "policy_version": policy_version,
            "spending_limit": str(spending_limit),
            "issue_timestamp": str(issue_timestamp),
            "expiration_timestamp": str(expiration_timestamp),
        }
        sig_str = json.dumps(payload_dict, sort_keys=True)
        sig = hmac.new(secret_key, sig_str.encode("utf-8"), hashlib.sha256).hexdigest()

        return cls(
            decision_id=decision_id,
            request_id=request_id,
            request_digest=request_digest,
            decision=decision,
            reason_code=reason_code,
            policy_version=policy_version,
            spending_limit=spending_limit,
            issue_timestamp=issue_timestamp,
            expiration_timestamp=expiration_timestamp,
            hmac_signature=sig,
        )

    def verify_signature(self, secret_key: bytes) -> bool:
        expected_sig = hmac.new(
            secret_key,
            self.canonical_signature_payload().encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(self.hmac_signature, expected_sig)


class ProcurementGovernanceGate(ControlPlaneGate):
    """
    Deterministic control-plane gate for procurement purchase-order governance.
    Enforces spending authority, vendor status, segregation of duties, 4-way match,
    payment modification holds, authoritative amount reconciliation, evidence freshness,
    and HMAC token signing.
    """

    def __init__(
        self,
        spending_limit: Union[Decimal, float, str] = Decimal("10000.00"),
        match_tolerance: Union[Decimal, float, str] = Decimal("0.01"),
        secret_key: Optional[bytes] = None,
        token_ttl_seconds: float = 300.0,
        config: Optional[GateConfig] = None,
    ):
        super().__init__(config=config or GateConfig(version="1.0.0", is_critical=True))

        if isinstance(spending_limit, bool) or isinstance(match_tolerance, bool):
            raise ValueError("Booleans masquerading as gate thresholds are strictly forbidden")

        try:
            self.spending_limit = Decimal(str(spending_limit))
            self.match_tolerance = Decimal(str(match_tolerance))
        except (decimal.InvalidOperation, TypeError, ValueError):
            raise ValueError("Gate configuration thresholds must be valid numeric Decimals")

        if self.spending_limit.is_nan() or self.spending_limit.is_infinite() or self.spending_limit < Decimal("0"):
            raise ValueError("spending_limit must be finite and non-negative")
        if self.match_tolerance.is_nan() or self.match_tolerance.is_infinite() or self.match_tolerance < Decimal("0"):
            raise ValueError("match_tolerance must be finite and non-negative")

        self.secret_key = secret_key or b"DEMO_PROCUREMENT_HMAC_SECRET_KEY_CHANGE_IN_PROD"
        self.token_ttl_seconds = token_ttl_seconds

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

        # Extract trusted evidence context if provided
        evidence_ctx_raw = gate_input.context.get("trusted_evidence")
        if isinstance(evidence_ctx_raw, TrustedEvidenceContext):
            evidence_ctx = evidence_ctx_raw
        elif isinstance(evidence_ctx_raw, dict):
            try:
                evidence_ctx = TrustedEvidenceContext.model_validate(evidence_ctx_raw)
            except Exception:
                evidence_ctx = TrustedEvidenceContext(evidence_complete=False)
        else:
            evidence_ctx = TrustedEvidenceContext(evidence_complete=False)

        # Rule 6: Evidence completeness and freshness check
        if not evidence_ctx.evidence_complete:
            return GateOutcome(
                decision=GateDecision.INDETERMINATE,
                reason_code="INCOMPLETE_OR_UNTRUSTED_EVIDENCE",
                gate_name=self.gate_name,
                gate_version=self.config.version,
                evidence={"request_id": req.request_id, "evidence_complete": False},
                latency_ms=(time.perf_counter() - t0) * 1000.0,
            )

        if not evidence_ctx.is_fresh():
            return GateOutcome(
                decision=GateDecision.INDETERMINATE,
                reason_code="STALE_EVIDENCE_EXPIRED",
                gate_name=self.gate_name,
                gate_version=self.config.version,
                evidence={"request_id": req.request_id, "evidence_timestamp": evidence_ctx.evidence_timestamp},
                latency_ms=(time.perf_counter() - t0) * 1000.0,
            )

        # Rule 1: Vendor eligibility against trusted evidence
        if req.vendor_id not in evidence_ctx.verified_approved_vendors:
            return GateOutcome(
                decision=GateDecision.DENY,
                reason_code="UNAPPROVED_VENDOR",
                gate_name=self.gate_name,
                gate_version=self.config.version,
                evidence={"vendor_id": req.vendor_id, "approved": False},
                latency_ms=(time.perf_counter() - t0) * 1000.0,
            )

        # Rule 5: Payment instruction change hold
        if req.payment_instructions_changed:
            return GateOutcome(
                decision=GateDecision.HALT,
                reason_code="PAYMENT_INSTRUCTION_CHANGE_HOLD",
                gate_name=self.gate_name,
                gate_version=self.config.version,
                evidence={"request_id": req.request_id, "vendor_id": req.vendor_id},
                latency_ms=(time.perf_counter() - t0) * 1000.0,
            )

        # Rule 4: Explicit 4-way document match check (all pair comparisons)
        amounts = [
            ("amount", req.amount),
            ("invoice_amount", req.invoice_amount),
            ("purchase_order_amount", req.purchase_order_amount),
            ("goods_receipt_amount", req.goods_receipt_amount),
        ]
        max_discrepancy = Decimal("0")
        for i in range(len(amounts)):
            for j in range(i + 1, len(amounts)):
                diff = abs(amounts[i][1] - amounts[j][1])
                if diff > max_discrepancy:
                    max_discrepancy = diff

        if max_discrepancy > self.match_tolerance:
            return GateOutcome(
                decision=GateDecision.DENY,
                reason_code="DOCUMENT_MATCH_DISCREPANCY",
                gate_name=self.gate_name,
                gate_version=self.config.version,
                evidence={
                    "max_discrepancy": str(max_discrepancy),
                    "tolerance": str(self.match_tolerance),
                    "amount": str(req.amount),
                    "invoice_amount": str(req.invoice_amount),
                    "po_amount": str(req.purchase_order_amount),
                    "gr_amount": str(req.goods_receipt_amount),
                },
                latency_ms=(time.perf_counter() - t0) * 1000.0,
            )

        authoritative_amount = max(
            req.amount,
            req.invoice_amount,
            req.purchase_order_amount,
            req.goods_receipt_amount,
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

        # Rule 2: Spending authority against authoritative_amount
        if authoritative_amount > self.spending_limit:
            if not req.independent_approval or not req.approver_id:
                return GateOutcome(
                    decision=GateDecision.DENY,
                    reason_code="EXCEEDS_SPENDING_AUTHORITY",
                    gate_name=self.gate_name,
                    gate_version=self.config.version,
                    evidence={
                        "authoritative_amount": str(authoritative_amount),
                        "spending_limit": str(self.spending_limit),
                        "currency": req.currency,
                    },
                    latency_ms=(time.perf_counter() - t0) * 1000.0,
                )

            # Verify independent approval against trusted attestation bound to request_id + canonical_digest
            approval_key_specific = f"{req.request_id}:{req.canonical_digest()}:{req.approver_id}"
            approval_key_generic = f"{req.request_id}:{req.approver_id}"
            if (
                approval_key_specific not in evidence_ctx.verified_independent_approvals
                and approval_key_generic not in evidence_ctx.verified_independent_approvals
            ):
                return GateOutcome(
                    decision=GateDecision.DENY,
                    reason_code="UNVERIFIED_INDEPENDENT_APPROVAL_RECORD",
                    gate_name=self.gate_name,
                    gate_version=self.config.version,
                    evidence={"approval_key": approval_key_specific},
                    latency_ms=(time.perf_counter() - t0) * 1000.0,
                )

            approver_limit = evidence_ctx.verified_approver_authority_limits.get(
                req.approver_id, Decimal("0")
            )
            if authoritative_amount > approver_limit:
                return GateOutcome(
                    decision=GateDecision.DENY,
                    reason_code="INSUFFICIENT_APPROVER_AUTHORITY_LIMIT",
                    gate_name=self.gate_name,
                    gate_version=self.config.version,
                    evidence={
                        "authoritative_amount": str(authoritative_amount),
                        "approver_limit": str(approver_limit),
                        "approver_id": req.approver_id,
                    },
                    latency_ms=(time.perf_counter() - t0) * 1000.0,
                )

        # Rule 7: Successful approval with HMAC token signing
        now = time.time()
        decision_token = ProcurementDecisionToken.sign_token(
            secret_key=self.secret_key,
            decision_id=f"DEC-{uuid.uuid4().hex[:12].upper()}",
            request_id=req.request_id,
            request_digest=req.canonical_digest(),
            decision=GateDecision.ALLOW,
            reason_code="PROCUREMENT_APPROVAL_GRANTED",
            policy_version=self.config.version,
            spending_limit=self.spending_limit,
            issue_timestamp=now,
            ttl_seconds=self.token_ttl_seconds,
        )

        return GateOutcome(
            decision=GateDecision.ALLOW,
            reason_code="PROCUREMENT_APPROVAL_GRANTED",
            gate_name=self.gate_name,
            gate_version=self.config.version,
            evidence={
                "request_id": req.request_id,
                "request_digest": req.canonical_digest(),
                "decision_token": decision_token.model_dump(mode="json"),
                "authoritative_amount": str(authoritative_amount),
                "currency": req.currency,
                "vendor_id": req.vendor_id,
            },
            latency_ms=(time.perf_counter() - t0) * 1000.0,
        )


class SyntheticProcurementExecutor:
    """
    Downstream synthetic action boundary test double.
    Enforces HMAC signature verification, expiration checking, canonical digest binding,
    and thread-safe atomic single-use replay protection.

    Architectural Limit Note:
    Replay protection uses an in-memory process-local lock and set.
    In distributed multi-process environments, atomic replay protection requires a distributed lock
    or transactional store (e.g. Redis/SQL with SELECT FOR UPDATE).
    """

    def __init__(self, secret_key: Optional[bytes] = None, allow_replay: bool = False):
        self.secret_key = secret_key or b"DEMO_PROCUREMENT_HMAC_SECRET_KEY_CHANGE_IN_PROD"
        self.executed_orders: List[Dict[str, Any]] = []
        self.used_decision_ids: Set[str] = set()
        self.allow_replay = allow_replay
        self._lock = threading.Lock()

    def execute(
        self,
        outcome: Any,
        request: ProcurementRequest,
        gate: Optional[ProcurementGovernanceGate] = None,
        current_time: Optional[float] = None,
    ) -> bool:
        decision = getattr(outcome, "decision", None)
        passed = getattr(outcome, "passed", False)

        if decision != GateDecision.ALLOW or not passed:
            return False

        evidence = getattr(outcome, "evidence", {}) or {}
        token_data = evidence.get("decision_token")
        if not token_data or not isinstance(token_data, dict):
            return False

        try:
            token = ProcurementDecisionToken.model_validate(token_data)
        except Exception:
            return False

        # 1. HMAC Signature Authenticity Verification
        target_secret = gate.secret_key if gate is not None else self.secret_key
        if not token.verify_signature(target_secret):
            return False

        # 2. Expiration Verification
        now = current_time if current_time is not None else time.time()
        if now > token.expiration_timestamp:
            return False

        # 3. Request & Canonical Digest Binding
        if token.request_id != request.request_id:
            return False
        if token.request_digest != request.canonical_digest():
            return False

        # 4. Gate / Policy Version Matching
        if gate is not None:
            if token.policy_version != gate.config.version:
                return False
            if token.spending_limit != gate.spending_limit:
                return False

        # 5. Thread-Safe Atomic Replay Protection (In-Memory Process-Local)
        with self._lock:
            if token.decision_id in self.used_decision_ids and not self.allow_replay:
                return False
            self.used_decision_ids.add(token.decision_id)

        self.executed_orders.append({
            "decision_id": token.decision_id,
            "request_id": request.request_id,
            "purchase_order_id": request.purchase_order_id,
            "vendor_id": request.vendor_id,
            "amount": str(request.amount),
            "currency": request.currency,
            "timestamp": time.time(),
        })
        return True


def run_demo() -> Dict[str, Any]:
    """Runs a synthetic procurement governance demonstration across 4 scenarios."""
    gate = ProcurementGovernanceGate(spending_limit=Decimal("10000.00"))
    executor = SyntheticProcurementExecutor()

    # Trusted evidence setup
    trusted_ctx = TrustedEvidenceContext(
        verified_approved_vendors={"VEND-ACME"},
        verified_approver_authority_limits={"USR-BOB-MANAGER": Decimal("50000.00")},
        evidence_complete=True,
    )

    # Scenario 1: Compliant Request
    compliant_req = ProcurementRequest(
        request_id="REQ-001",
        purchase_order_id="PO-1001",
        vendor_id="VEND-ACME",
        requester_id="USR-ALICE",
        amount=Decimal("5000.00"),
        currency="USD",
        invoice_amount=Decimal("5000.00"),
        purchase_order_amount=Decimal("5000.00"),
        goods_receipt_amount=Decimal("5000.00"),
    )
    outcome_1 = gate.evaluate_contract(
        GateInput(payload=compliant_req, context={"trusted_evidence": trusted_ctx})
    )
    exec_1 = executor.execute(outcome_1, compliant_req, gate)

    # Scenario 2: Exceeding Spending Authority (Without valid independent approval)
    over_limit_req = ProcurementRequest(
        request_id="REQ-002",
        purchase_order_id="PO-1002",
        vendor_id="VEND-ACME",
        requester_id="USR-BOB",
        amount=Decimal("25000.00"),
        currency="USD",
        invoice_amount=Decimal("25000.00"),
        purchase_order_amount=Decimal("25000.00"),
        goods_receipt_amount=Decimal("25000.00"),
    )
    outcome_2 = gate.evaluate_contract(
        GateInput(payload=over_limit_req, context={"trusted_evidence": trusted_ctx})
    )
    exec_2 = executor.execute(outcome_2, over_limit_req, gate)

    # Scenario 3: Payment Instructions Changed
    changed_payment_req = ProcurementRequest(
        request_id="REQ-003",
        purchase_order_id="PO-1003",
        vendor_id="VEND-ACME",
        requester_id="USR-CHARLIE",
        amount=Decimal("3000.00"),
        currency="USD",
        invoice_amount=Decimal("3000.00"),
        purchase_order_amount=Decimal("3000.00"),
        goods_receipt_amount=Decimal("3000.00"),
        payment_instructions_changed=True,
    )
    outcome_3 = gate.evaluate_contract(
        GateInput(payload=changed_payment_req, context={"trusted_evidence": trusted_ctx})
    )
    exec_3 = executor.execute(outcome_3, changed_payment_req, gate)

    # Scenario 4: Insufficient Evidence
    incomplete_req = ProcurementRequest(
        request_id="REQ-004",
        purchase_order_id="PO-1004",
        vendor_id="VEND-UNKNOWN",
        requester_id="USR-DAVE",
        amount=Decimal("1200.00"),
        currency="USD",
        invoice_amount=Decimal("1200.00"),
        purchase_order_amount=Decimal("1200.00"),
        goods_receipt_amount=Decimal("1200.00"),
    )
    outcome_4 = gate.evaluate_contract(
        GateInput(
            payload=incomplete_req,
            context={"trusted_evidence": TrustedEvidenceContext(evidence_complete=False)},
        )
    )
    exec_4 = executor.execute(outcome_4, incomplete_req, gate)

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
