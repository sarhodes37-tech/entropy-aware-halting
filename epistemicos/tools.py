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

        # SEC-03: Determine action mutability
        from epistemicos.action_policy import ActionRegistry, ActionCategory
        self.action_registry = getattr(registry, "action_registry", None) or ActionRegistry()
        self.action_category = self.action_registry.classify_action(self.action_name)
        self.is_read_only = self.action_category in (
            ActionCategory.READ_ONLY_LOCAL,
            ActionCategory.NETWORK_READ
        )

        # Validate inspectable executor signature
        try:
            self._executor_sig = inspect.signature(self._executor_func)
        except Exception as e:
            if not self.is_read_only:
                raise ValueError(f"TrustedToolWrapper initialization failed: Executor signature must be inspectable for mutating operation '{self.action_name}' ({str(e)})") from e
            self._executor_sig = None

        # Validate that target_param exists in executor's inspectable signature
        if self.target_param and self._executor_sig:
            if self.target_param not in self._executor_sig.parameters:
                raise ValueError(
                    f"TrustedToolWrapper initialization failed: target_param '{self.target_param}' does not exist in executor signature parameters: {list(self._executor_sig.parameters.keys())}"
                )

        # Register executor with the underlying authority
        if self.registry and self.registry.authority:
            self.registry.authority.register_executor(self.executor_id, self._executor_func)

    def _extract_actual_target(self, args: Tuple[Any, ...], kwargs: Dict[str, Any]) -> str:
        """
        Determines the actual resource target accessed by this tool invocation deterministically.
        SEC-03: For state-mutating operations:
        - Requires explicit target_extractor or explicit target_param (or keyword 'target').
        - Strictly rejects ambiguous positional string fallback.
        - Strictly rejects conflicting target values across parameter sources.
        - Fails closed on unknown or unclassified actions.
        """
        targets_found = {}

        # 1. Custom extractor
        if self.target_extractor:
            try:
                extracted = self.target_extractor(*args, **kwargs)
                if not extracted or not isinstance(extracted, str) or not extracted.strip():
                    raise PermissionError(f"Tool target extraction failed closed: Custom extractor returned invalid target '{extracted}'")
                targets_found["target_extractor"] = extracted.strip()
            except Exception as e:
                if isinstance(e, PermissionError):
                    raise
                raise PermissionError(f"Tool target extraction failed closed: {str(e)}") from e

        # 2. Explicit target_param declared at registration
        if self.target_param:
            if self.target_param in kwargs and kwargs[self.target_param]:
                val = str(kwargs[self.target_param]).strip()
                if val:
                    targets_found["target_param_kwarg"] = val
            try:
                sig = inspect.signature(self._executor_func)
                bound_args = sig.bind_partial(*args, **kwargs)
                if self.target_param in bound_args.arguments and bound_args.arguments[self.target_param]:
                    val = str(bound_args.arguments[self.target_param]).strip()
                    if val:
                        targets_found["target_param_bound"] = val
            except (ValueError, TypeError):
                pass

        # 3. Explicit 'target' parameter in kwargs
        if "target" in kwargs and kwargs["target"]:
            val = str(kwargs["target"]).strip()
            if val:
                targets_found["explicit_target_kwarg"] = val

        # 4. Resource argument inference in kwargs / signature-bound args
        resource_keys = ("path", "file", "filepath", "node", "endpoint", "url", "resource", "filename", "destination")
        for r_key in resource_keys:
            if r_key in kwargs and kwargs[r_key]:
                val = str(kwargs[r_key]).strip()
                if val:
                    targets_found[f"resource_kwarg_{r_key}"] = val

        try:
            sig = inspect.signature(self._executor_func)
            bound_args = sig.bind_partial(*args, **kwargs)
            for r_key in resource_keys:
                if r_key in bound_args.arguments and bound_args.arguments[r_key]:
                    val = str(bound_args.arguments[r_key]).strip()
                    if val:
                        targets_found[f"resource_bound_{r_key}"] = val
        except (ValueError, TypeError):
            pass

        # Check for conflicting targets among explicit sources
        distinct_targets = set(targets_found.values())
        if len(distinct_targets) > 1:
            raise PermissionError(
                f"Tool execution rejected: Conflicting target values detected across parameters for tool '{self.tool_id}': {distinct_targets}"
            )

        if distinct_targets:
            return distinct_targets.pop()

        # SEC-03: Positional argument fallback is permitted ONLY for demonstrably read-only actions
        if self.is_read_only:
            if args and isinstance(args[0], str) and args[0].strip():
                return args[0].strip()

        # Default target fallback (safe only if configured and no conflicting args)
        if self.default_target:
            # For mutating actions without explicit target_param or extractor, reject execution if dynamic args were supplied
            if not self.is_read_only and not self.target_param and not self.target_extractor and (args or kwargs):
                raise PermissionError(
                    f"Tool execution rejected: State-mutating tool '{self.tool_id}' requires explicit target_param or target_extractor and cannot rely on default_target when arguments are supplied"
                )
            return self.default_target

        if not self.is_read_only:
            raise PermissionError(
                f"Tool execution rejected: State-mutating operation '{self.action_name}' requires explicit target parameter ('target_param' or 'target_extractor') and rejects ambiguous positional fallback"
            )

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

        boundary = self.registry.execution_boundary
        authority = self.registry.authority

        # SEC-01: Establish authenticated principal assertion
        from epistemicos.authorization import AuthenticatedPrincipal
        auth_principal_input = (
            exec_context.get("authenticated_principal")
            or kwargs.get("authenticated_principal")
        )

        active_policy = self.tool_policy or authority.default_policy

        if auth_principal_input is not None:
            if not isinstance(auth_principal_input, AuthenticatedPrincipal):
                raise PermissionError("Tool execution rejected: authenticated_principal must be an instance of AuthenticatedPrincipal")
            valid, p_reason, pid = authority.principal_provider.verify_principal(auth_principal_input)
            if not valid:
                raise PermissionError(f"Tool execution rejected: Principal authentication failed ({p_reason})")
            effective_principal = auth_principal_input
        else:
            # Check for unauthenticated caller-controlled principal spoofing
            claimed_pid = exec_context.get("principal_id") or kwargs.get("principal_id")
            if claimed_pid and claimed_pid != "agent_default":
                raise PermissionError(f"Tool execution rejected: Caller-controlled context dictionary cannot assert principal identity '{claimed_pid}' without AuthenticatedPrincipal")

            # Check if active policy requires privileged principal
            if active_policy and active_policy.allowed_principals != {"*"}:
                raise PermissionError("Tool execution rejected: Policy requires authenticated principal but none provided")
            effective_principal = "agent_default"

        payload_digest = boundary.compute_canonical_digest(raw_payload)

        # Authoritative policy resolution: Tool-bound policy FIRST, then authority default_policy.
        # Invocation-supplied policy overrides are strictly rejected.
        active_policy = self.tool_policy or authority.default_policy

        # Reconstruct call_kwargs for underlying executor if target parameter was bound by wrapper signature
        call_kwargs = dict(kwargs)
        # Strip control-plane wrapper parameters from call_kwargs if not accepted by executor signature
        try:
            sig = inspect.signature(self._executor_func)
            sig_params = sig.parameters
            for control_key in ("authenticated_principal", "principal_id", "policy", "task_contract", "human_approval"):
                if control_key in call_kwargs and control_key not in sig_params:
                    call_kwargs.pop(control_key, None)

            if "target" in sig_params and "target" not in call_kwargs and exec_target is not None:
                call_kwargs["target"] = exec_target

            # SEC-03: Verify that authorized target is exactly the resource targeted by the executor
            bound_for_exec = sig.bind_partial(*args, **call_kwargs)

            # 1. Verify standard target_param if registered
            if self.target_param and self.target_param in bound_for_exec.arguments:
                bound_val = str(bound_for_exec.arguments[self.target_param]).strip()
                if bound_val != exec_target:
                    raise PermissionError(
                        f"Tool execution rejected: Authorized target '{exec_target}' differs from executor target parameter '{bound_val}' (via target_param '{self.target_param}')"
                    )

            # 2. Check all recognized target parameter names
            recognized_target_names = ("target", "path", "file", "filepath", "node", "endpoint", "url", "resource", "filename", "destination")
            for param_name in recognized_target_names:
                if param_name in bound_for_exec.arguments:
                    bound_val = str(bound_for_exec.arguments[param_name]).strip()
                    if bound_val and bound_val != exec_target:
                        raise PermissionError(
                            f"Tool execution rejected: Authorized target '{exec_target}' differs from executor target parameter '{bound_val}' (via parameter '{param_name}')"
                        )

            # 3. Verifiable binding contract for mutating operations:
            # Check any string argument whose parameter name implies resource/identity targeting
            if not self.is_read_only:
                target_like_keywords = ("key", "id", "account", "table", "db", "entity", "dest", "item", "record")
                found_bound_target = False
                for p_name, p_val in bound_for_exec.arguments.items():
                    if isinstance(p_val, str) and str(p_val).strip() == exec_target:
                        found_bound_target = True
                    elif isinstance(p_val, str) and any(k in p_name.lower() for k in target_like_keywords):
                        bound_str = str(p_val).strip()
                        if bound_str and bound_str != exec_target:
                            raise PermissionError(
                                f"Tool execution rejected: Authorized target '{exec_target}' differs from executor argument '{bound_str}' (via parameter '{p_name}')"
                            )

                # If dynamic args were supplied to mutating action, at least one argument must bind to the authorized target
                if (args or call_kwargs) and not found_bound_target and not self.default_target:
                    raise PermissionError(
                        f"Tool execution rejected: Verifiable target binding contract failed; no executor argument bound to authorized target '{exec_target}'"
                    )

        except PermissionError:
            raise
        except (ValueError, TypeError) as bind_err:
            if not self.is_read_only:
                raise PermissionError(
                    f"Tool execution rejected: Signature binding failure for mutating operation '{self.action_name}': {str(bind_err)}"
                ) from bind_err

        # Construct bound 0-arg closure for TrustedExecutionBoundary
        def _exec_closure():
            return self._executor_func(*args, **call_kwargs)

        # Evaluate against AuthorizationAuthority and issue capability for _exec_closure
        cap, reason = authority.evaluate_and_issue_capability(
            action_name=self.action_name,
            target=exec_target,
            canonical_request_digest=payload_digest,
            principal_id=effective_principal,
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
            required_success_evidence=set(cap.required_success_evidence) if cap.required_success_evidence else set(),
            fencing_token=cap.fencing_token,
            scope_key=cap.scope_key,
            authenticated_principal=effective_principal
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
