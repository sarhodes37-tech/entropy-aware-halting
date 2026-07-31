import math
import re
import time
from typing import Dict, Any, Tuple, Optional, List
from dataclasses import dataclass
from enum import Enum

from epistemicos.audit import TamperEvidentAuditTrail, AuditLogLevel


class GateAction(Enum):
    ALLOW = "ALLOW"
    HALT = "DETERMINISTIC_HALT"
    ROLLBACK = "ACTION_ROLLBACK"


@dataclass
class GateResult:
    action: GateAction
    latency_ms: float
    gate_name: str
    reason: Optional[str] = None


class OptimizedEntropyGate:
    """
    Evaluates Shannon Entropy and Z-score variance using O(1) streaming updates
    to intercept structural collapse, N-gram loops, and epistemic hallucination states.
    """
    def __init__(self, z_threshold: float = 3.2, max_window: int = 64):
        self.z_threshold = z_threshold
        self.max_window = max_window
        self.rolling_entropy: List[float] = []

    def evaluate_token_logits(self, logits: List[float]) -> GateResult:
        t0 = time.perf_counter()

        # 1. Compute Shannon Entropy H(X) = -sum(P(x) * log2(P(x)))
        # Softmax normalization
        max_logit = max(logits)
        exps = [math.exp(l - max_logit) for l in logits]
        sum_exps = sum(exps)
        probs = [e / sum_exps for e in exps]

        entropy = -sum(p * math.log2(p) for p in probs if p > 1e-12)

        self.rolling_entropy.append(entropy)
        if len(self.rolling_entropy) > self.max_window:
            self.rolling_entropy.pop(0)

        # 2. O(1) Streaming Z-Score Calculation
        n = len(self.rolling_entropy)
        if n > 5:
            mean = sum(self.rolling_entropy) / n
            variance = sum((x - mean) ** 2 for x in self.rolling_entropy) / n
            std_dev = math.sqrt(variance) if variance > 1e-9 else 1e-9

            z_score = abs(entropy - mean) / std_dev

            # Anomaly Trigger: Near-zero entropy collapse (looping/hallucinating absolute certainty)
            if z_score > self.z_threshold and entropy < 0.05:
                latency = (time.perf_counter() - t0) * 1000
                return GateResult(
                    action=GateAction.HALT,
                    latency_ms=latency,
                    gate_name="EntropyGate",
                    reason=f"Anomalous Entropy Collapse (Z-Score: {z_score:.2f}, H(X): {entropy:.4f})"
                )

        latency = (time.perf_counter() - t0) * 1000
        return GateResult(action=GateAction.ALLOW, latency_ms=latency, gate_name="EntropyGate")


class OptimizedPermissionGate:
    """
    Pre-compiled JIT Schema Gate enforcing strict contract boundaries,
    intercepting unauthorized tool calls and sandbox escape attempts.
    """
    def __init__(self, allowed_actions: List[str]):
        self.allowed_actions = set(allowed_actions)
        # Pre-compile regex for tool/function call identification
        self.tool_call_regex = re.compile(r"<tool_call>.*?\"name\":\s*\"([^\"]+)\".*?</tool_call>", re.DOTALL)
        self.system_cmd_regex = re.compile(r"(sudo|rm\s+-rf|curl|wget|bash|sh|exec)\s+", re.IGNORECASE)

    def evaluate_payload(self, raw_output: str) -> GateResult:
        t0 = time.perf_counter()

        # Check 1: Tool Call Contract Bounding
        tool_matches = self.tool_call_regex.findall(raw_output)
        for tool_name in tool_matches:
            if tool_name not in self.allowed_actions:
                latency = (time.perf_counter() - t0) * 1000
                return GateResult(
                    action=GateAction.ROLLBACK,
                    latency_ms=latency,
                    gate_name="PermissionGate",
                    reason=f"Unauthorized Function Call Attempted: '{tool_name}'"
                )

        # Check 2: Unsafe Command Execution Escapes
        if self.system_cmd_regex.search(raw_output):
            latency = (time.perf_counter() - t0) * 1000
            return GateResult(
                action=GateAction.ROLLBACK,
                latency_ms=latency,
                gate_name="PermissionGate",
                reason="Unsafe System Command Injection Intercepted"
            )

        latency = (time.perf_counter() - t0) * 1000
        return GateResult(action=GateAction.ALLOW, latency_ms=latency, gate_name="PermissionGate")


class EpistemicOrchestrator:
    """
    The main runtime wrapper coordinating low-latency hard gates and
    cryptographic audit logging.
    """
    def __init__(
        self,
        allowed_tools: List[str],
        model_id: str = "target-llm-v1",
        log_file_path: Optional[str] = None
    ):
        self.entropy_gate = OptimizedEntropyGate()
        self.permission_gate = OptimizedPermissionGate(allowed_actions=allowed_tools)
        self.model_id = model_id
        
        if log_file_path:
            self.audit_logger = TamperEvidentAuditTrail(log_file_path=log_file_path)
        else:
            self.audit_logger = TamperEvidentAuditTrail()

    def process_step(
        self,
        token_logits: List[float],
        accumulated_output: str
    ) -> Tuple[GateAction, float, List[str]]:
        t_start = time.perf_counter()
        reasons = []

        # Stream evaluation 1: Entropy Gate
        e_res = self.entropy_gate.evaluate_token_logits(token_logits)
        if e_res.action != GateAction.ALLOW:
            total_latency = (time.perf_counter() - t_start) * 1000
            reason_str = e_res.reason or "Entropy Violation"
            reasons.append(reason_str)

            # Record Cryptographic Audit Entry
            self.audit_logger.record_event(
                event_type=AuditLogLevel.HALT,
                gate_name=e_res.gate_name,
                reason=reason_str,
                model_id=self.model_id,
                execution_latency_ms=total_latency,
                payload_snippet=accumulated_output
            )
            return e_res.action, total_latency, reasons

        # Stream evaluation 2: Permission Gate
        p_res = self.permission_gate.evaluate_payload(accumulated_output)
        if p_res.action != GateAction.ALLOW:
            total_latency = (time.perf_counter() - t_start) * 1000
            reason_str = p_res.reason or "Permission Boundary Violation"
            reasons.append(reason_str)

            # Record Cryptographic Audit Entry
            self.audit_logger.record_event(
                event_type=AuditLogLevel.ROLLBACK,
                gate_name=p_res.gate_name,
                reason=reason_str,
                model_id=self.model_id,
                execution_latency_ms=total_latency,
                payload_snippet=accumulated_output
            )
            return p_res.action, total_latency, reasons

        total_latency = (time.perf_counter() - t_start) * 1000
        return GateAction.ALLOW, total_latency, []
