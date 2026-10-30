"""
EpistemicOS Trusted Tool Registration & Invocation Layer.

Provides a fail-closed tool wrapper and registry (`TrustedToolRegistry`, `TrustedToolWrapper`)
that binds registered callable tools directly to EpistemicOS's authoritative authorization
authority (`AuthorizationAuthority`) and execution boundary (`TrustedExecutionBoundary`).
"""

import time
import uuid
import inspect
from dataclasses import dataclass, field
from typing import Dict, Any, Callable, Optional, Tuple, Set, Union

from epistemicos.authorization import (
    AuthorizationAuthority,
    Policy,
    TrustedTaskContract,
    Capability,
    HumanApprovalRecord,
    get_callable_identity,
)
from epistemicos.provenance import (
    TrustedExecutionBoundary,
    ExecutionContext,
)
from epistemicos.core import EpistemicOrchestrator


class TrustedToolWrapper:
    """
    Fail-closed wrapper for an agent-facing callable tool.
    Routes every invocation through AuthorizationAuthority and TrustedExecutionBoundary.
    Binds policy authorization strictly to the actual resource target accessed by the executor.
    """

    def __init__(
        self,
        tool_id: str,
        action_name: str,
        executor_func: Callable[..., Any],
        registry: "TrustedToolRegistry",
        default_target: Optional[str] = None,
        target_param: Optional[str] = None,
        target_extractor: Optional[Callable[..., str]] = None,
        policy: Optional[Policy] = None,
        description: str = ""
    ):
        if not tool_id or not isinstance(tool_id, str) or not tool_id.strip():
            raise ValueError("TrustedToolWrapper initialization failed: tool_id must be a non-empty string")

        if not action_name or not isinstance(action_name, str) or not action_name.strip():
            raise ValueError("TrustedToolWrapper initialization failed: action_name must be a non-empty string")

        if not callable(executor_func):
            raise ValueError("TrustedToolWrapper initialization failed: executor_func must be a callable object")

        self.tool_id = tool_id.strip()
        self.action_name = action_name.strip()
        self._executor_func = executor_func
        self.registry = registry
        self.default_target = default_target.strip() if default_target and isinstance(default_target, str) else None
        self.target_param = target_param.strip() if target_param and isinstance(target_param, str) else None
        self.target_extractor = target_extractor if callable(target_extractor) else None
        self.tool_policy = policy  # Authoritative policy bound at tool registration time
        self.description = description
        self.executor_id = get_callable_identity(executor_func)

        # Register executor with the underlying authority
        if self.registry and self.registry.authority:
            self.registry.authority.register_executor(self.executor_id, self._executor_func)

    def _extract_actual_target(self, args: Tuple[Any, ...], kwargs: Dict[str, Any]) -> str:
        """
        Determines the actual resource target accessed by this tool invocation.
        Precedence order:
        1. Explicit target_extractor function declared at registration.
        2. Explicit target_param declared at registration (searched in kwargs or positional args).
        3. Explicit 'target' parameter passed in kwargs.
        4. Resource argument inference in kwargs/args (checking 'path', 'file', 'filepath', 'node', 'endpoint', 'url', 'resource').
        5. First positional string argument.
        6. Default target configured at tool registration.
        Fails closed if no target can be established.
        """
        # 1. Custom extractor
        if self.target_extractor:
            try:
                extracted = self.target_extractor(*args, **kwargs)
                if extracted and isinstance(extracted, str) and extracted.strip():
                    return extracted.strip()
            except Exception as e:
                raise PermissionError(f"Tool target extraction failed closed: {str(e)}")

        # 2. Explicit target_param declared at registration
        if self.target_param:
            if self.target_param in kwargs and kwargs[self.target_param]:
                val = str(kwargs[self.target_param]).strip()
                if val:
                    return val
            # Try binding positional args to signature
            try:
                sig = inspect.signature(self._executor_func)
                bound_args = sig.bind_partial(*args, **kwargs)
                if self.target_param in bound_args.arguments and bound_args.arguments[self.target_param]:
                    val = str(bound_args.arguments[self.target_param]).strip()
                    if val:
                        return val
            except (ValueError, TypeError):
                pass

        # 3. Explicit 'target' parameter in kwargs
        if "target" in kwargs and kwargs["target"]:
            val = str(kwargs["target"]).strip()
            if val:
                return val

        # 4. Infer resource target parameter names in kwargs / bound args
        resource_keys = ("path", "file", "filepath", "node", "endpoint", "url", "resource", "filename", "destination")
        for r_key in resource_keys:
            if r_key in kwargs and kwargs[r_key]:
                val = str(kwargs[r_key]).strip()
                if val:
                    return val

        try:
            sig = inspect.signature(self._executor_func)
            bound_args = sig.bind_partial(*args, **kwargs)
            for r_key in resource_keys:
                if r_key in bound_args.arguments and bound_args.arguments[r_key]:
                    val = str(bound_args.arguments[r_key]).strip()
                    if val:
                        return val
        except (ValueError, TypeError):
            pass

        # 5. First positional string argument if positional args provided
        if args and isinstance(args[0], str) and args[0].strip():
            return args[0].strip()

        # 6. Default target configured at tool registration
        if self.default_target:
            return self.default_target

        raise PermissionError(f"Tool execution rejected: Unable to determine actual resource target for tool '{self.tool_id}'")

    def __call__(
        self,
        *args,
        context: Optional[Dict[str, Any]] = None,
        task_contract: Optional[Union[TrustedTaskContract, Dict[str, Any]]] = None,
        human_approval: Optional[HumanApprovalRecord] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Agent-facing invocation entry point.
        Evaluates authorization, issues single-use capability, and executes via TrustedExecutionBoundary.
        Note: Untrusted callers CANNOT supply a custom Policy parameter in __call__ to override authorization.
        Policy strictly originates from tool registration configuration or authority default_policy.
        """
        if not self.registry:
            raise PermissionError("Tool execution rejected: Unbound tool wrapper missing TrustedToolRegistry reference")

        # Determine actual resource target accessed
        exec_target = self._extract_actual_target(args, kwargs)

        raw_payload = {
            "tool_id": self.tool_id,
            "action_name": self.action_name,
            "target": exec_target,
            "args": args,
            "kwargs": kwargs
        }

        exec_context = dict(context or {})
        task_id_val = exec_context.get("task_id")
        corr_id = exec_context.get("correlation_id") or str(uuid.uuid4())
        req_id = exec_context.get("request_id") or str(uuid.uuid4())
        # Principal ID must strictly originate from verified context or default
        principal_id = exec_context.get("principal_id", "agent_default")

        boundary = self.registry.execution_boundary
        authority = self.registry.authority

        payload_digest = boundary.compute_canonical_digest(raw_payload)

        # Authoritative policy resolution: Tool-bound policy FIRST, then authority default_policy.
        # Invocation-supplied policy overrides are strictly rejected.
        active_policy = self.tool_policy or authority.default_policy

        # Reconstruct call_kwargs for underlying executor if target parameter was bound by wrapper signature
        call_kwargs = dict(kwargs)
        try:
            sig_params = inspect.signature(self._executor_func).parameters
            if "target" in sig_params and "target" not in call_kwargs and exec_target is not None:
                call_kwargs["target"] = exec_target
        except (ValueError, TypeError):
            pass

        # Construct bound 0-arg closure for TrustedExecutionBoundary
        def _exec_closure():
            return self._executor_func(*args, **call_kwargs)

        # Evaluate against AuthorizationAuthority and issue capability for _exec_closure
        cap, reason = authority.evaluate_and_issue_capability(
            action_name=self.action_name,
            target=exec_target,
            canonical_request_digest=payload_digest,
            principal_id=principal_id,
            correlation_id=corr_id,
            request_id=req_id,
            executor_id=_exec_closure,
            policy=active_policy,
            human_approval_input=human_approval or exec_context.get("human_approval"),
            task_contract=task_contract or exec_context.get("task_contract"),
            task_id=task_id_val
        )

        if not cap:
            raise PermissionError(f"Tool execution rejected by AuthorizationAuthority: {reason}")

        boundary_ctx = ExecutionContext(
            correlation_id=corr_id,
            request_id=req_id,
            authorization_token_id=cap.token_id,
            authorized_digest=payload_digest,
            authorization_granted=True,
            policy_version=cap.policy_version,
            task_id=cap.task_id,
            contract_version=cap.contract_version,
            required_success_evidence=set(cap.required_success_evidence) if cap.required_success_evidence else set()
        )

        # Record AUTHORIZATION_GRANTED event in provenance store
        from epistemicos.provenance import ProvenanceEvent, ProvenanceEventType, ProvenanceSource
        grant_event = ProvenanceEvent(
            schema_version="1.0.0",
            event_id=str(uuid.uuid4()),
            event_type=ProvenanceEventType.AUTHORIZATION_GRANTED.value,
            provenance_source=ProvenanceSource.GOVERNANCE_GATE.value,
            correlation_id=corr_id,
            request_id=req_id,
            action_name=self.action_name,
            target=exec_target,
            canonical_request_digest=payload_digest,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            authorization_token_id=cap.token_id,
            policy_version=cap.policy_version
        )
        boundary.store.record_event(grant_event)

        # Execute through TrustedExecutionBoundary with cleanup
        try:
            res = boundary.execute_protected_action(
                action_name=self.action_name,
                target=exec_target,
                request_payload=raw_payload,
                executor_func=_exec_closure,
                context=boundary_ctx
            )
            return res
        finally:
            if cap and authority and hasattr(authority, "executor_registry"):
                exec_reg = authority.executor_registry
                if hasattr(exec_reg, "_pop_internal"):
                    exec_reg._pop_internal(cap.token_id, None)
                else:
                    exec_reg.pop(cap.token_id, None)


class TrustedToolRegistry:
    """
    Authoritative Tool Registry binding registered callables to EpistemicOS authorization.
    Maintains a mapping of tool_id -> TrustedToolWrapper.
    """

    def __init__(
        self,
        orchestrator: Optional[EpistemicOrchestrator] = None,
        authority: Optional[AuthorizationAuthority] = None,
        execution_boundary: Optional[TrustedExecutionBoundary] = None
    ):
        if orchestrator:
            self.orchestrator = orchestrator
            self.execution_boundary = orchestrator.execution_boundary
            self.authority = orchestrator.authority
        else:
            self.execution_boundary = execution_boundary or TrustedExecutionBoundary()
            self.authority = authority or getattr(self.execution_boundary, "authority", None) or AuthorizationAuthority()
            self.orchestrator = None

        self._tools: Dict[str, TrustedToolWrapper] = {}

    def register_tool(
        self,
        tool_id: str,
        action_name: str,
        executor_func: Callable[..., Any],
        default_target: Optional[str] = None,
        target_param: Optional[str] = None,
        target_extractor: Optional[Callable[..., str]] = None,
        policy: Optional[Policy] = None,
        description: str = ""
    ) -> TrustedToolWrapper:
        """
        Registers a tool callable, wrapping it in a fail-closed TrustedToolWrapper.
        Enforces target extraction parameters and authoritative tool-bound policies.
        """
        wrapper = TrustedToolWrapper(
            tool_id=tool_id,
            action_name=action_name,
            executor_func=executor_func,
            registry=self,
            default_target=default_target,
            target_param=target_param,
            target_extractor=target_extractor,
            policy=policy,
            description=description
        )
        self._tools[wrapper.tool_id] = wrapper
        return wrapper

    def get_tool(self, tool_id: str) -> Optional[TrustedToolWrapper]:
        """Retrieves a registered TrustedToolWrapper."""
        return self._tools.get(tool_id)

    def list_tools(self) -> Dict[str, str]:
        """Lists registered tools with descriptions."""
        return {t_id: wrap.description for t_id, wrap in self._tools.items()}
