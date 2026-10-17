"""
EpistemicOS Governance Gates Suite.

Defines abstract base interfaces and concrete implementations for the 
unified pipeline. These gates act as a defense-in-depth security layer,
intercepting adversarial prompt injections, data washing, and cryptographic
compromises before they can mutate the stateful database.

Components:
- EntropyGate: Token Surprisal & Latent Anomaly Detection
- PermissionGate: Scope, Sandbox, & Action Boundary Validation
- TriangulationGate: Data Washing & Synthetic Index Inflation Defense
- CryptoAttestationGate: Post-Quantum Attestation & OCSP Revocation
"""

from abc import ABC, abstractmethod
import os
import re
import time
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from enum import Enum
from epistemicos.models import TokenSurprisalSensor


class GateAction(Enum):
    ALLOW = "ALLOW"
    HALT = "DETERMINISTIC_HALT"
    ROLLBACK = "ACTION_ROLLBACK"


class GateDecision(Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    HALT = "HALT"
    INDETERMINATE = "INDETERMINATE"


@dataclass
class GateInput:
    payload: Dict[str, Any]
    context: Dict[str, Any]
    operation_id: Optional[str] = None
    requestor_id: Optional[str] = None
    attempt_number: int = 1


@dataclass
class GateConfig:
    """
    Versioned gate configuration.
    Note: max_execution_cost_ms is an advisory execution envelope parameter used for
    telemetry profiling and budget tracking; it does not forcibly interrupt execution threads.
    """
    version: str = "1.0.0"
    is_critical: bool = True
    max_execution_cost_ms: float = 100.0
    enabled: bool = True
    custom_params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GateOutcome:
    decision: GateDecision
    reason_code: str
    gate_name: str
    gate_version: str = "1.0.0"
    evidence: Dict[str, Any] = field(default_factory=dict)
    latency_ms: float = 0.0
    cost_estimate_ms: float = 0.0

    @property
    def passed(self) -> bool:
        return self.decision == GateDecision.ALLOW

    @property
    def action(self) -> GateAction:
        return GateAction.ALLOW if self.decision == GateDecision.ALLOW else GateAction.HALT

    @property
    def status(self) -> str:
        return "ALLOWED" if self.decision == GateDecision.ALLOW else "HALTED"

    @property
    def reason(self) -> str:
        return self.reason_code

    def to_audit_event(self) -> Dict[str, Any]:
        return {
            "gate_name": self.gate_name,
            "gate_version": self.gate_version,
            "decision": self.decision.value,
            "reason_code": self.reason_code,
            "evidence": self.evidence,
            "latency_ms": self.latency_ms,
            "cost_estimate_ms": self.cost_estimate_ms,
            "timestamp": time.time()
        }

    def to_gate_result(self) -> "GateResult":
        if self.decision == GateDecision.ALLOW:
            action = GateAction.ALLOW
            status = "ALLOWED"
        else:
            action = GateAction.HALT
            status = "HALTED"

        kwargs = dict(self.evidence)
        kwargs.setdefault("status", status)
        kwargs.setdefault("action", action)
        kwargs.setdefault("gate_name", self.gate_name)
        kwargs.setdefault("reason", self.reason_code)
        kwargs.setdefault("latency_ms", self.latency_ms)
        kwargs.setdefault("confidence", 1.0 if self.decision == GateDecision.ALLOW else 0.0)

        return GateResult(**kwargs)


@dataclass
class GateResult:
    def __init__(
        self,
        status="ALLOWED",
        action=GateAction.ALLOW,
        gate=None,
        gate_name=None,
        reason="",
        flagged_tokens=0,
        divergence=0.0,
        confidence=1.0,
        latency_ms=0.0,
        vectors_revoked=0,
        **kwargs
    ):
        # Normalize status vs action to handle both keyword styles seamlessly
        if isinstance(action, GateAction):
            self.action = action
            self.status = "ALLOWED" if action == GateAction.ALLOW else "HALTED"
        else:
            self.status = status
            self.action = GateAction.ALLOW if status == "ALLOWED" else GateAction.HALT

        # Assign gate and gate_name interchangeably so either attribute is always valid
        resolved_gate = gate or gate_name
        self.gate = resolved_gate
        self.gate_name = resolved_gate

        self.reason = reason
        self.flagged_tokens = flagged_tokens
        self.divergence = divergence
        self.confidence = confidence
        self.latency_ms = latency_ms
        self.vectors_revoked = vectors_revoked or (flagged_tokens if action != GateAction.ALLOW else 0)

        for k, v in kwargs.items():
            setattr(self, k, v)

    def __getitem__(self, key):
        if key == "status":
            return self.status
        if key == "action":
            return self.action
        if key == "passed":
            return self.passed
        if key == "vectors_revoked":
            return self.vectors_revoked
        if key == "gate":
            return self.gate
        if key == "gate_name":
            return self.gate_name
        return getattr(self, key)

    def get(self, key, default=None):
        try:
            return self[key]
        except (AttributeError, KeyError):
            return default

    @property
    def passed(self) -> bool:
        """Compatibility adapter for orchestrator check engine expectations."""
        return self.action == GateAction.ALLOW


class Gate(ABC):
    """Base interface for all EpistemicOS governance plugins."""

    @abstractmethod
    def evaluate(self, payload: Dict[str, Any], context: Dict[str, Any]) -> GateResult:
        """
        Evaluates payload and runtime context.
        Must return a GateResult dictating the deterministic action.
        """
        pass


class ControlPlaneGate(Gate):
    """Refined abstract base class for independent control-plane gates with typed input/outcome contract."""

    def __init__(self, config: Optional[GateConfig] = None):
        self.config = config or GateConfig()
        self.gate_name = self.__class__.__name__

    @abstractmethod
    def evaluate_contract(self, gate_input: GateInput) -> GateOutcome:
        """Typed input/outcome evaluation method."""
        pass

    def evaluate_safe(self, gate_input: GateInput) -> GateOutcome:
        """Evaluates contract with fail-closed exception handling."""
        t0 = time.perf_counter()
        try:
            return self.evaluate_contract(gate_input)
        except Exception as e:
            latency = (time.perf_counter() - t0) * 1000.0
            gate_name = getattr(self, "gate_name", self.__class__.__name__)
            cfg = getattr(self, "config", None)
            is_critical = getattr(cfg, "is_critical", True)
            gate_version = getattr(cfg, "version", "1.0.0")

            if is_critical:
                return GateOutcome(
                    decision=GateDecision.HALT,
                    reason_code="GATE_EXECUTION_ERROR",
                    gate_name=gate_name,
                    gate_version=gate_version,
                    evidence={"error": str(e), "exception_type": type(e).__name__},
                    latency_ms=latency
                )
            else:
                return GateOutcome(
                    decision=GateDecision.INDETERMINATE,
                    reason_code="GATE_EXECUTION_ERROR_NON_CRITICAL",
                    gate_name=gate_name,
                    gate_version=gate_version,
                    evidence={"error": str(e)},
                    latency_ms=latency
                )

    def evaluate(self, payload: Dict[str, Any], context: Dict[str, Any]) -> GateResult:
        """Legacy adapter for evaluate(payload, context)."""
        gi = GateInput(
            payload=payload,
            context=context,
            operation_id=context.get("requested_operation_id") or context.get("operation_name"),
            requestor_id=context.get("requestor_id"),
            attempt_number=context.get("attempt_number", 1)
        )
        outcome = self.evaluate_safe(gi)
        return outcome.to_gate_result()


class EntropyGate(ControlPlaneGate):
    """
    Monitors autoregressive token logprobs for anomaly detection using a 
    granular, token-by-token surprisal sensor.
    """

    def __init__(
        self,
        z_threshold: float = 2.85,
        window_size: int = 10,
        strict_mode: bool = False,
        max_surprisal_ceiling: Optional[float] = 10.0,
        config: Optional[GateConfig] = None
    ):
        super().__init__(config=config or GateConfig(version="1.0.0", is_critical=True))
        self.sensor = TokenSurprisalSensor(
            z_threshold=z_threshold,
            window_size=window_size,
            max_surprisal_ceiling=max_surprisal_ceiling
        )
        self.strict_mode = strict_mode

    def evaluate_contract(self, gate_input: GateInput) -> GateOutcome:
        t0 = time.perf_counter()
        logprobs = gate_input.context.get("token_logprobs", [])

        if not logprobs:
            if self.strict_mode or self.config.custom_params.get("strict_mode", False):
                return GateOutcome(
                    decision=GateDecision.HALT,
                    reason_code="MISSING_LOGPROBS_STRICT_MODE",
                    gate_name=self.gate_name,
                    gate_version=self.config.version,
                    evidence={"confidence": 0.0, "status": "HALTED"},
                    latency_ms=(time.perf_counter() - t0) * 1000
                )
            return GateOutcome(
                decision=GateDecision.ALLOW,
                reason_code="NO_LOGPROBS_PROVIDED",
                gate_name=self.gate_name,
                gate_version=self.config.version,
                latency_ms=(time.perf_counter() - t0) * 1000
            )

        sensor_result = self.sensor.evaluate(logprobs)

        if not sensor_result["passed"]:
            flagged_count = sensor_result.get('flagged_tokens', 1)
            reason_msg = sensor_result.get("error") if sensor_result.get("reason") == "MALFORMED_NON_FINITE_LOGPROBS" else f"Anomalous Token Surprisal Detected (Max Z: {sensor_result['max_z_score']:.2f}, Flagged: {flagged_count})"
            return GateOutcome(
                decision=GateDecision.HALT,
                reason_code=reason_msg,
                gate_name=self.gate_name,
                gate_version=self.config.version,
                evidence={
                    "flagged_tokens": flagged_count,
                    "vectors_revoked": max(1, flagged_count),
                    "confidence": 0.0
                },
                latency_ms=(time.perf_counter() - t0) * 1000
            )

        return GateOutcome(
            decision=GateDecision.ALLOW,
            reason_code="SURPRISAL_WITHIN_BOUNDS",
            gate_name=self.gate_name,
            gate_version=self.config.version,
            latency_ms=(time.perf_counter() - t0) * 1000
        )


class PermissionGate(ControlPlaneGate):
    """
    Pre-compiled JIT Schema Gate enforcing strict contract boundaries.
    """

    def __init__(
        self,
        contract_model: Any = None,
        allowed_actions: Optional[List[str]] = None,
        trusted_operations: Optional[Dict[str, Any]] = None,
        trusted_scope: Optional[Dict[str, Any]] = None,
        config: Optional[GateConfig] = None
    ):
        super().__init__(config=config or GateConfig(version="1.0.0", is_critical=True))
        self.contract_model = contract_model
        self.allowed_actions = set(allowed_actions or [])
        self.trusted_operations = trusted_operations or {}
        self.trusted_scope = trusted_scope

        self.injection_regex = re.compile(
            r"(\b(sudo|rm|curl|wget|bash|sh|exec|nc|netcat|nmap|ping)\b|[;|`]|&&|\$\(|\[SYSTEM OVERRIDE\]|import\s+os|ignore previous instructions|system prompt|jailbreak|exfiltrate|web_search)", 
            re.IGNORECASE
        )

    def _enforce_contract_model(self, llm_output: Any, t0: float) -> Optional[GateOutcome]:
        if self.contract_model is not None and llm_output is not None:
            try:
                if isinstance(llm_output, dict):
                    self.contract_model(**llm_output)
                elif hasattr(self.contract_model, "model_validate"):
                    self.contract_model.model_validate(llm_output)
            except Exception as e:
                return GateOutcome(
                    decision=GateDecision.HALT,
                    reason_code=f"Contract Schema Violation: {str(e)}",
                    gate_name=self.gate_name,
                    gate_version=self.config.version,
                    evidence={"status": "HALTED", "confidence": 0.0, "vectors_revoked": 1},
                    latency_ms=(time.perf_counter() - t0) * 1000
                )
        return None

    @staticmethod
    def _extract_action_details(action: Any) -> tuple[Optional[str], Optional[str]]:
        """
        Extracts operation ('op') and target/resource ('node', 'endpoint', or 'policy')
        from a proposed action dictionary or object, supporting nested action representations.
        """
        if action is None:
            return None, None

        inner_action = None
        if isinstance(action, dict):
            inner_action = action.get("action")
        elif hasattr(action, "action"):
            inner_action = getattr(action, "action")

        target_obj = inner_action if (inner_action is not None and (isinstance(inner_action, dict) or hasattr(inner_action, "__dict__") or hasattr(inner_action, "op"))) else action

        if isinstance(target_obj, dict):
            op = target_obj.get("op")
            node = target_obj.get("node") or target_obj.get("endpoint") or target_obj.get("policy") or target_obj.get("resource") or target_obj.get("target")
        else:
            op = getattr(target_obj, "op", None)
            node = getattr(target_obj, "node", None) or getattr(target_obj, "endpoint", None) or getattr(target_obj, "policy", None) or getattr(target_obj, "resource", None) or getattr(target_obj, "target", None)

        if not op and target_obj is not action:
            if isinstance(action, dict):
                op = action.get("op")
            else:
                op = getattr(action, "op", None)

        if not node and target_obj is not action:
            if isinstance(action, dict):
                node = action.get("node") or action.get("endpoint") or action.get("policy") or action.get("resource") or action.get("target")
            else:
                node = getattr(action, "node", None) or getattr(action, "endpoint", None) or getattr(action, "policy", None) or getattr(action, "resource", None) or getattr(action, "target", None)

        return op, node

    def _validate_actions(self, scope: Dict[str, Any], proposed_actions: List[Any], t0: float) -> Optional[GateOutcome]:
        allowed_ops = scope.get("allowed_operations")
        allowed_res = scope.get("allowed_resources")
        is_rmm_origin = scope.get("is_rmm_origin", False)

        if allowed_ops is None and allowed_res is None and not self.allowed_actions and not is_rmm_origin:
            return None

        for action in proposed_actions:
            op, node = self._extract_action_details(action)

            if allowed_ops is not None and op not in allowed_ops:
                return GateOutcome(
                    decision=GateDecision.HALT,
                    reason_code=f"Operation '{op}' outside allowed scope operations: {allowed_ops}",
                    gate_name=self.gate_name,
                    gate_version=self.config.version,
                    evidence={"status": "HALTED", "confidence": 0.0},
                    latency_ms=(time.perf_counter() - t0) * 1000
                )

            if allowed_res is not None and node is not None and node not in allowed_res:
                return GateOutcome(
                    decision=GateDecision.HALT,
                    reason_code=f"Resource node '{node}' outside allowed scope resources: {allowed_res}",
                    gate_name=self.gate_name,
                    gate_version=self.config.version,
                    evidence={"status": "HALTED", "confidence": 0.0},
                    latency_ms=(time.perf_counter() - t0) * 1000
                )

            if self.allowed_actions and op not in self.allowed_actions:
                return GateOutcome(
                    decision=GateDecision.HALT,
                    reason_code=f"Operation '{op}' not in gate allowed_actions",
                    gate_name=self.gate_name,
                    gate_version=self.config.version,
                    evidence={"status": "HALTED", "confidence": 0.0},
                    latency_ms=(time.perf_counter() - t0) * 1000
                )

            if is_rmm_origin and op in {"update_db", "issue_binder", "api_call", "web_search"}:
                return GateOutcome(
                    decision=GateDecision.HALT,
                    reason_code="Downstream Scope Lock: State-mutating action prohibited from RMM quarantine subnet.",
                    gate_name=self.gate_name,
                    gate_version=self.config.version,
                    evidence={"status": "HALTED", "confidence": 0.0},
                    latency_ms=(time.perf_counter() - t0) * 1000
                )
        return None

    def _deep_regex_inspection(self, payload: Dict[str, Any], proposed_actions: List[Any], llm_output: Any, t0: float) -> Optional[GateOutcome]:
        def _check_stack(obj: Any) -> bool:
            if not obj:
                return False
            stack = [obj]
            seen = set()
            search = self.injection_regex.search
            add_seen = seen.add
            pop = stack.pop
            append = stack.append
            scalar_types = frozenset({int, float, bool, bytes, bytearray, type(None)})

            while stack:
                curr = pop()
                cls = curr.__class__

                if cls is str:
                    if search(curr):
                        return True
                    continue

                if cls in scalar_types:
                    continue

                curr_id = id(curr)
                if curr_id in seen:
                    continue
                add_seen(curr_id)

                if isinstance(curr, dict):
                    for k, v in curr.items():
                        if isinstance(k, str):
                            if search(k):
                                return True
                        else:
                            append(k)
                        append(v)
                elif cls in (list, tuple, set) or isinstance(curr, (list, tuple, set)):
                    for item in curr:
                        append(item)
                elif hasattr(curr, "__dict__"):
                    append(curr.__dict__)

            return False

        if _check_stack(payload) or _check_stack(proposed_actions) or _check_stack(llm_output):
            return GateOutcome(
                decision=GateDecision.HALT,
                reason_code="Unsafe Command Injection, Jailbreak, or System Override Intercepted",
                gate_name=self.gate_name,
                gate_version=self.config.version,
                evidence={"status": "HALTED", "confidence": 0.0, "vectors_revoked": 1},
                latency_ms=(time.perf_counter() - t0) * 1000
            )
        return None

    def evaluate_contract(self, gate_input: GateInput) -> GateOutcome:
        t0 = time.perf_counter()
        payload = gate_input.payload
        context = gate_input.context

        actual_exec = context.get("actual_executable") or context.get("executable_operation")
        requested_op = gate_input.operation_id or context.get("requested_operation_id") or context.get("operation_name")

        if actual_exec:
            is_trusted_match = False
            if self.trusted_operations:
                if not requested_op or requested_op not in self.trusted_operations:
                    return GateOutcome(
                        decision=GateDecision.HALT,
                        reason_code=f"Operation '{requested_op}' is not registered in trusted operations registry.",
                        gate_name=self.gate_name,
                        gate_version=self.config.version,
                        evidence={"status": "HALTED", "confidence": 0.0},
                        latency_ms=(time.perf_counter() - t0) * 1000
                    )
                registered_func = self.trusted_operations[requested_op]
                if actual_exec is not registered_func:
                    return GateOutcome(
                        decision=GateDecision.HALT,
                        reason_code=f"Executable identity mismatch for operation '{requested_op}': substituted executable detected.",
                        gate_name=self.gate_name,
                        gate_version=self.config.version,
                        evidence={"status": "HALTED", "confidence": 0.0},
                        latency_ms=(time.perf_counter() - t0) * 1000
                    )
                is_trusted_match = True

            if self.allowed_actions:
                exec_name = getattr(actual_exec, "__name__", str(actual_exec))
                if exec_name not in self.allowed_actions and not (is_trusted_match and requested_op in self.allowed_actions):
                    return GateOutcome(
                        decision=GateDecision.HALT,
                        reason_code=f"Resolved executable '{exec_name}' or operation '{requested_op}' not in gate allowed_actions: {self.allowed_actions}",
                        gate_name=self.gate_name,
                        gate_version=self.config.version,
                        evidence={"status": "HALTED", "confidence": 0.0},
                        latency_ms=(time.perf_counter() - t0) * 1000
                    )

        # Security Hardening: Authorization Scope Resolution
        # Priority: self.trusted_scope (gate config) > context.get("trusted_scope") > context.get("scope") > payload.scope
        trusted_scope_raw = (
            self.trusted_scope
            if self.trusted_scope is not None
            else context.get("trusted_scope")
            if context.get("trusted_scope") is not None
            else context.get("scope")
            if context.get("scope") is not None
            else getattr(payload, "scope", None)
            if hasattr(payload, "scope")
            else payload.get("scope")
            if isinstance(payload, dict)
            else None
        )

        if trusted_scope_raw is not None:
            if isinstance(trusted_scope_raw, dict):
                trusted_scope = trusted_scope_raw
            elif hasattr(trusted_scope_raw, "model_dump"):
                trusted_scope = trusted_scope_raw.model_dump()
            elif hasattr(trusted_scope_raw, "__dict__"):
                trusted_scope = trusted_scope_raw.__dict__
            else:
                trusted_scope = trusted_scope_raw
        else:
            trusted_scope = {}

        proposed_actions = context.get("proposed_actions", []) or payload.get("proposed_actions", [])
        llm_output = context.get("llm_output") or payload.get("llm_output")

        # Require explicit, non-ambiguous action contract details (both operation AND target/resource)
        if proposed_actions:
            for act in proposed_actions:
                op_val, node_val = self._extract_action_details(act)

                if not op_val or not isinstance(op_val, str) or not op_val.strip():
                    return GateOutcome(
                        decision=GateDecision.HALT,
                        reason_code="Missing or invalid operation identifier in proposed action",
                        gate_name=self.gate_name,
                        gate_version=self.config.version,
                        evidence={"status": "HALTED", "confidence": 0.0},
                        latency_ms=(time.perf_counter() - t0) * 1000
                    )
                if not node_val or not isinstance(node_val, str) or not node_val.strip():
                    return GateOutcome(
                        decision=GateDecision.HALT,
                        reason_code="Missing or invalid target/resource identifier in proposed action",
                        gate_name=self.gate_name,
                        gate_version=self.config.version,
                        evidence={"status": "HALTED", "confidence": 0.0},
                        latency_ms=(time.perf_counter() - t0) * 1000
                    )

        contract_result = self._enforce_contract_model(llm_output, t0)
        if contract_result:
            return contract_result

        actions_result = self._validate_actions(trusted_scope, proposed_actions, t0)
        if actions_result:
            return actions_result

        regex_result = self._deep_regex_inspection(payload, proposed_actions, llm_output, t0)
        if regex_result:
            return regex_result

        return GateOutcome(
            decision=GateDecision.ALLOW,
            reason_code="PERMISSION_SCOPE_VALIDATED",
            gate_name=self.gate_name,
            gate_version=self.config.version,
            evidence={"status": "ALLOWED"},
            latency_ms=(time.perf_counter() - t0) * 1000
        )


class TriangulationGate(ControlPlaneGate):
    """
    Input Integrity and Telemetry Cross-Check Module.
    """

    def __init__(self, max_divergence_threshold: float = 0.15, strict_mode: bool = False, config: Optional[GateConfig] = None):
        super().__init__(config=config or GateConfig(version="1.0.0", is_critical=True))
        self.max_divergence_threshold = max_divergence_threshold
        self.strict_mode = strict_mode

    def evaluate_contract(self, gate_input: GateInput) -> GateOutcome:
        t0 = time.perf_counter()
        payload = gate_input.payload
        context = gate_input.context

        primary = payload.get("primary_metric")
        telemetry = context.get("heterogeneous_telemetry", payload.get("heterogeneous_telemetry", []))

        if primary is None or not telemetry:
            if self.strict_mode or self.config.custom_params.get("strict_mode", False):
                return GateOutcome(
                    decision=GateDecision.HALT,
                    reason_code="MISSING_TELEMETRY_STRICT_MODE",
                    gate_name=self.gate_name,
                    gate_version=self.config.version,
                    evidence={"confidence": 0.0, "status": "HALTED"},
                    latency_ms=(time.perf_counter() - t0) * 1000
                )
            return GateOutcome(
                decision=GateDecision.ALLOW,
                reason_code="TELEMETRY_NOT_PROVIDED",
                gate_name=self.gate_name,
                gate_version=self.config.version,
                latency_ms=(time.perf_counter() - t0) * 1000
            )

        try:
            primary = float(primary)
            telemetry = [float(x) for x in telemetry]
            baseline_mean = sum(telemetry) / len(telemetry)

            divergence = 0.0 if baseline_mean == 0 else abs(primary - baseline_mean) / abs(baseline_mean)

            if divergence > self.max_divergence_threshold:
                return GateOutcome(
                    decision=GateDecision.HALT,
                    reason_code=f"Data Washing Detected: Metric diverged {divergence:.1%} from baseline.",
                    gate_name=self.gate_name,
                    gate_version=self.config.version,
                    evidence={"divergence": divergence, "confidence": 0.0},
                    latency_ms=(time.perf_counter() - t0) * 1000
                )
        except (ValueError, TypeError):
            return GateOutcome(
                decision=GateDecision.HALT,
                reason_code="Malformed telemetry data type.",
                gate_name=self.gate_name,
                gate_version=self.config.version,
                evidence={"divergence": 1.0, "confidence": 0.0},
                latency_ms=(time.perf_counter() - t0) * 1000
            )

        return GateOutcome(
            decision=GateDecision.ALLOW,
            reason_code="TELEMETRY_TRIANGULATED",
            gate_name=self.gate_name,
            gate_version=self.config.version,
            evidence={"divergence": divergence},
            latency_ms=(time.perf_counter() - t0) * 1000
        )


class CryptoAttestationGate(ControlPlaneGate):
    """
    Evaluates cryptographic health, OCSP Key Revocation State, 
    and Quantum Trust Epochs.
    """

    def __init__(
        self,
        required_algorithm: str = "ML-DSA",
        expiry_year: int = 2030,
        revoked_keys: Optional[frozenset] = None,
        config: Optional[GateConfig] = None
    ):
        super().__init__(config=config or GateConfig(version="1.0.0", is_critical=True))
        self.required_algorithm = required_algorithm
        self.expiry_year = expiry_year
        self.revoked_keys = revoked_keys if revoked_keys is not None else frozenset(k.strip() for k in os.getenv("EPISTEMICOS_REVOKED_KEYS", "").split(",")) if os.getenv("EPISTEMICOS_REVOKED_KEYS") else frozenset()

    def _check_ocsp_revocation(self, key_id: str) -> bool:
        return key_id in self.revoked_keys

    def evaluate_contract(self, gate_input: GateInput) -> GateOutcome:
        t0 = time.perf_counter()
        payload = gate_input.payload
        context = gate_input.context

        crypto_meta = context.get("cryptography") or payload.get("raw_payload", {}).get("cryptography", {})
        algo = crypto_meta.get("algorithm", "RSA-2048")
        key_id = crypto_meta.get("key_id", "UNKNOWN_KEY")

        if self._check_ocsp_revocation(key_id):
            return GateOutcome(
                decision=GateDecision.HALT,
                reason_code=f"CRITICAL: Key {key_id} is flagged as REVOKED by OCSP.",
                gate_name=self.gate_name,
                gate_version=self.config.version,
                evidence={"confidence": 0.0},
                latency_ms=(time.perf_counter() - t0) * 1000
            )

        if algo != self.required_algorithm:
            return GateOutcome(
                decision=GateDecision.HALT,
                reason_code=f"Deprecated algorithm {algo}. Requires quantum-resistant {self.required_algorithm}",
                gate_name=self.gate_name,
                gate_version=self.config.version,
                evidence={"confidence": 0.15},
                latency_ms=(time.perf_counter() - t0) * 1000
            )

        return GateOutcome(
            decision=GateDecision.ALLOW,
            reason_code="CRYPTO_ATTESTATION_VALIDATED",
            gate_name=self.gate_name,
            gate_version=self.config.version,
            latency_ms=(time.perf_counter() - t0) * 1000
        )
