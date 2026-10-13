"""
Shower Curtain Main Orchestration Engine.

Orchestrates Stages A through E for outbound requests and
inbound response inspection/rehydration.
"""

import json
import uuid
import copy
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple, Set

from epistemicos.audit import TamperEvidentAuditTrail, AuditEvent, AuditLogLevel, ReceiptGenerator, _sanitize_sensitive_data
from epistemicos.gates import GateAction, GateResult
from epistemicos.shower_curtain.detector import SensitiveDataDetector, SensitivityCategory, DetectionResult
from epistemicos.shower_curtain.policy import PrivacyPolicy, PrivacyTreatment, PolicyDecision
from epistemicos.shower_curtain.vault import LocalMappingVault
from epistemicos.shower_curtain.context import ContextMinimizationBroker
from epistemicos.shower_curtain.mpu import MarginalPrivacyUtilityEvaluator, MPUResult
from epistemicos.shower_curtain.gate import ShowerCurtainGate


@dataclass
class PrivacyTransformationResult:
    original_payload: Dict[str, Any]
    sanitized_payload: Dict[str, Any]
    session_id: str
    transaction_id: str
    detections: List[DetectionResult]
    decisions: List[PolicyDecision]
    mpu_result: Optional[MPUResult]
    gate_result: GateResult
    audit_receipt: Optional[Dict[str, Any]] = None
    dry_run: bool = False
    preview_payload: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "transaction_id": self.transaction_id,
            "dry_run": self.dry_run,
            "gate_passed": self.gate_result.action == GateAction.ALLOW,
            "detections_count": len(self.detections),
            "decisions": [d.to_dict() for d in self.decisions],
            "mpu_result": self.mpu_result.__dict__ if self.mpu_result else None,
            "gate_result": {
                "action": self.gate_result.action.value,
                "reason": self.gate_result.reason
            },
            "audit_receipt": self.audit_receipt,
            "preview_payload": self.preview_payload
        }


class ShowerCurtainEngine:
    """
    Local-first privacy mediation engine orchestrating detector, policy,
    vault, context broker, MPU, egress gate, and audit receipts.
    """

    def __init__(
        self,
        detector: Optional[SensitiveDataDetector] = None,
        policy: Optional[PrivacyPolicy] = None,
        vault: Optional[LocalMappingVault] = None,
        context_broker: Optional[ContextMinimizationBroker] = None,
        mpu_evaluator: Optional[MarginalPrivacyUtilityEvaluator] = None,
        egress_gate: Optional[ShowerCurtainGate] = None,
        audit_log_path: str = "logs/shower_curtain_audit.jsonl"
    ):
        self.detector = detector or SensitiveDataDetector()
        self.policy = policy or PrivacyPolicy()
        self.vault = vault or LocalMappingVault()
        self.context_broker = context_broker or ContextMinimizationBroker()
        self.mpu_evaluator = mpu_evaluator or MarginalPrivacyUtilityEvaluator()
        self.egress_gate = egress_gate or ShowerCurtainGate(detector=self.detector, policy=self.policy)
        self.audit_logger = TamperEvidentAuditTrail(log_file_path=audit_log_path)

    def _sanitize_text(
        self,
        text: str,
        session_id: str,
        all_detections: List[DetectionResult],
        all_decisions: List[PolicyDecision],
        dry_run: bool = False
    ) -> str:
        if not text:
            return text

        detections = self.detector.detect(text)
        if not detections:
            return text

        # Sort detections in reverse order of span start to replace right-to-left without shifting indices
        detections.sort(key=lambda d: d.span[0], reverse=True)
        sanitized = text

        for det in detections:
            all_detections.append(det)
            decision = self.policy.evaluate(det)
            all_decisions.append(decision)

            treatment = decision.treatment
            val = det.value
            start, end = det.span

            if treatment == PrivacyTreatment.PASS:
                continue
            elif treatment == PrivacyTreatment.REDACT:
                placeholder = f"[REDACTED_{det.category.value}]"
                sanitized = sanitized[:start] + placeholder + sanitized[end:]
            elif treatment == PrivacyTreatment.PSEUDONYMIZE:
                if dry_run:
                    placeholder = f"[PSEUDONYM_{det.category.value}_PREVIEW]"
                else:
                    placeholder = self.vault.get_or_create_pseudonym(session_id, det)
                sanitized = sanitized[:start] + placeholder + sanitized[end:]
            elif treatment == PrivacyTreatment.GENERALIZE:
                if det.category == SensitivityCategory.FILE_PATH:
                    placeholder = "[REDACTED_FILE_PATH]"
                elif det.category == SensitivityCategory.IP_ADDRESS:
                    placeholder = "[REDACTED_IP_SUBNET]"
                else:
                    placeholder = f"[GENERALIZED_{det.category.value}]"
                sanitized = sanitized[:start] + placeholder + sanitized[end:]
            elif treatment == PrivacyTreatment.TRANSFORM:
                transformer = self.policy.transformers.get(det.category)
                if transformer:
                    transformed_val = transformer(val)
                    sanitized = sanitized[:start] + transformed_val + sanitized[end:]
                else:
                    placeholder = f"[BLOCKED_{det.category.value}]"
                    sanitized = sanitized[:start] + placeholder + sanitized[end:]
            elif treatment == PrivacyTreatment.BLOCK:
                placeholder = f"[BLOCKED_{det.category.value}]"
                sanitized = sanitized[:start] + placeholder + sanitized[end:]

        return sanitized

    def transform_request(
        self,
        payload: Dict[str, Any],
        session_id: Optional[str] = None,
        dry_run: bool = False,
        estimated_utility_gain: float = 0.8,
        context: Optional[Dict[str, Any]] = None
    ) -> PrivacyTransformationResult:
        ctx = dict(context) if context else {}
        sess_id = session_id or str(uuid.uuid4())
        tx_id = str(uuid.uuid4())

        all_detections: List[DetectionResult] = []
        all_decisions: List[PolicyDecision] = []

        # Copy payload for transformation
        working_payload = copy.deepcopy(payload)

        # Stage D: Context Minimization on message histories if present
        if "messages" in working_payload and isinstance(working_payload["messages"], list):
            working_payload["messages"] = self.context_broker.trim_messages(working_payload["messages"])

        # Stage D: Filter context chunks if present in payload or context
        if "context_chunks" in working_payload and isinstance(working_payload["context_chunks"], list):
            working_payload["context_chunks"] = self.context_broker.filter_context_chunks(working_payload["context_chunks"])

        # Stages A, B, C: Traverse and sanitize payload fields
        def _traverse_and_sanitize(obj: Any) -> Any:
            if isinstance(obj, str):
                return self._sanitize_text(obj, sess_id, all_detections, all_decisions, dry_run=dry_run)
            elif isinstance(obj, dict):
                return {k: _traverse_and_sanitize(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [_traverse_and_sanitize(item) for item in obj]
            return obj

        transformed_payload = _traverse_and_sanitize(working_payload)

        # In dry_run mode, sanitized_payload remains the unmodified input payload, while preview_payload holds preview
        final_sanitized_payload = copy.deepcopy(payload) if dry_run else transformed_payload
        preview_payload = transformed_payload if dry_run else None

        # Check if any BLOCK or unhandled TRANSFORM decision was produced
        has_blocked_treatment = any(
            d.treatment in (PrivacyTreatment.BLOCK, PrivacyTreatment.TRANSFORM)
            and not (d.treatment == PrivacyTreatment.TRANSFORM and d.detection.category in self.policy.transformers)
            for d in all_decisions
        )

        # Inject registered session placeholders into context for egress gate verification
        registered_placeholders = self.vault.get_session_placeholders(sess_id)
        ctx["registered_placeholders"] = registered_placeholders

        # Stage D (MPU Evaluation)
        mpu_res = self.mpu_evaluator.evaluate_disclosure(
            estimated_utility_gain=estimated_utility_gain,
            detections=all_detections
        )

        # Stage E: Egress Gate evaluates proposed transformed transmission payload
        eval_target = transformed_payload
        if has_blocked_treatment:
            blocked_cats = sorted(set(d.detection.category.value for d in all_decisions if d.treatment == PrivacyTreatment.BLOCK or (d.treatment == PrivacyTreatment.TRANSFORM and d.detection.category not in self.policy.transformers)))
            gate_res = GateResult(
                action=GateAction.HALT,
                status="HALTED",
                latency_ms=0.0,
                gate_name="ShowerCurtainGate",
                reason=f"Egress Gate Denied: Privacy policy BLOCK treatment triggered for {', '.join(blocked_cats)}.",
                confidence=0.0,
                vectors_revoked=1
            )
        else:
            gate_res = self.egress_gate.evaluate(eval_target, ctx)

        # Audit receipt generation with safe serialization (no raw PII)
        receipt_gen = ReceiptGenerator(gate_version="ShowerCurtain-1.0.0")
        receipt_gen.log_event("OutboundSanitization", {
            "session_id": sess_id,
            "dry_run": dry_run,
            "detections_count": len(all_detections),
            "decisions": [d.to_dict() for d in all_decisions],
            "mpu": mpu_res.__dict__ if mpu_res else None,
            "gate_action": gate_res.action.value
        })

        receipt = receipt_gen.mint_receipt(
            transaction_id=tx_id,
            success=(gate_res.action == GateAction.ALLOW),
            confidence_matrix={"privacy_gate": 1.0 if gate_res.action == GateAction.ALLOW else 0.0},
            decision_details={"gate_reason": gate_res.reason}
        )

        # Record event in audit trail
        audit_level = AuditLogLevel.INFO if gate_res.action == GateAction.ALLOW else AuditLogLevel.HALT
        self.audit_logger.record_event(AuditEvent(
            event_type=audit_level,
            gate_name="ShowerCurtainEngine",
            reason=gate_res.reason,
            model_id=ctx.get("model_id", "external_provider"),
            payload_snippet=json.dumps({"session_id": sess_id, "detections_count": len(all_detections)})
        ))

        return PrivacyTransformationResult(
            original_payload=payload,
            sanitized_payload=final_sanitized_payload,
            session_id=sess_id,
            transaction_id=tx_id,
            detections=all_detections,
            decisions=all_decisions,
            mpu_result=mpu_res,
            gate_result=gate_res,
            audit_receipt=receipt,
            dry_run=dry_run,
            preview_payload=preview_payload
        )

    def process_response(
        self,
        response_payload: Any,
        session_id: str,
        allow_rehydration: bool = True
    ) -> Any:
        """
        Inspects remote model response, detects leaks, and performs
        controlled rehydration of authorized session pseudonyms.
        """
        if not allow_rehydration or not response_payload:
            return response_payload

        # 1. Inspect response text before rehydration for raw sensitive data or policy violations
        response_str = json.dumps(response_payload) if not isinstance(response_payload, str) else response_payload
        raw_detections = self.detector.detect(response_str)

        # Check for prohibited raw secrets/credentials in response
        if any(d.category == SensitivityCategory.CREDENTIAL for d in raw_detections):
            raise ValueError("Shower Curtain Response Inspection Error: Remote provider output contains prohibited credentials.")

        # Evaluate policy decisions for raw sensitive items found in remote response
        for det in raw_detections:
            decision = self.policy.evaluate(det)
            if decision.treatment in (PrivacyTreatment.BLOCK, PrivacyTreatment.REDACT):
                raise ValueError(f"Shower Curtain Response Inspection Error: Remote provider output exposed raw sensitive item ({det.category.value}).")

        # 2. Controlled rehydration: Restore ONLY exact placeholders registered to the authorized session in the vault
        authorized_placeholders = self.vault.get_session_placeholders(session_id)

        def _rehydrate_obj(obj: Any) -> Any:
            if isinstance(obj, str):
                return self.vault.rehydrate(session_id, obj, allowed_placeholders=authorized_placeholders)
            elif isinstance(obj, dict):
                return {k: _rehydrate_obj(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [_rehydrate_obj(item) for item in obj]
            return obj

        return _rehydrate_obj(response_payload)
