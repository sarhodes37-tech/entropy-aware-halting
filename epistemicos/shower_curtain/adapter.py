"""
Provider Adapter Interface for Shower Curtain.

Demonstrates an OpenAI-compatible / generic LLM provider middleware adapter
wrapping model calls with outbound privacy transformations, egress policy verification,
and inbound rehydration.
"""

from typing import Dict, Any, Callable, Optional
from epistemicos.shower_curtain.engine import ShowerCurtainEngine, PrivacyTransformationResult
from epistemicos.gates import GateAction
from epistemicos.containment import EgressTransportBroker, EgressPolicy, ActionCategory


class ShowerCurtainOpenAIAdapter:
    """
    OpenAI-compatible / generic provider middleware adapter.
    Integrates ShowerCurtain privacy transformations with EgressTransportBroker
    to verify network egress before transmission to external model inference endpoints.
    """

    def __init__(
        self,
        engine: Optional[ShowerCurtainEngine] = None,
        egress_broker: Optional[EgressTransportBroker] = None,
        provider_endpoint_url: str = "https://api.openai.com/v1/chat/completions"
    ):
        self.engine = engine or ShowerCurtainEngine()
        self.provider_endpoint_url = provider_endpoint_url

        if egress_broker is None:
            # Default policy allowing provider endpoint
            policy = EgressPolicy(
                allowed_destinations={"api.openai.com", "api.anthropic.com"},
                allowed_categories={ActionCategory.NETWORK_READ}
            )
            self.egress_broker = EgressTransportBroker(policy=policy)
        else:
            self.egress_broker = egress_broker

    def execute_completion(
        self,
        completion_func: Callable[[Dict[str, Any]], Dict[str, Any]],
        request_payload: Dict[str, Any],
        session_id: Optional[str] = None,
        dry_run: bool = False,
        provider_url: Optional[str] = None
    ) -> Dict[str, Any]:
        target_url = provider_url or self.provider_endpoint_url

        # 1. Outbound transformation (Stage A-E)
        transform_res: PrivacyTransformationResult = self.engine.transform_request(
            payload=request_payload,
            session_id=session_id,
            dry_run=dry_run
        )

        # 2. Check ShowerCurtain Privacy Gate
        if transform_res.gate_result.action != GateAction.ALLOW:
            raise PermissionError(
                f"Shower Curtain Egress Gate Denied Request: {transform_res.gate_result.reason}"
            )

        # 3. Check Transport Egress Broker before external transmission
        allowed, reason, pinned_ip = self.egress_broker.establish_connection(
            target_url=target_url,
            action_name="inference_provider_request",
            correlation_id=session_id or transform_res.session_id,
            request_id=transform_res.transaction_id,
            category=ActionCategory.NETWORK_READ
        )
        if not allowed:
            raise PermissionError(
                f"Egress Broker Denied Provider Transmission: {reason}"
            )

        # 4. Handle Dry Run - NEVER invoke completion_func or external provider
        if dry_run:
            return {
                "dry_run": True,
                "sanitized_payload": transform_res.sanitized_payload,
                "preview_payload": transform_res.preview_payload,
                "transformation_report": transform_res.to_dict(),
                "egress_pinned_ip": pinned_ip
            }

        # 5. Invoke Remote Provider with Sanitized Payload
        raw_response = completion_func(transform_res.sanitized_payload)

        # 6. Inbound Response Processing & Controlled Rehydration
        rehydrated_response = self.engine.process_response(
            response_payload=raw_response,
            session_id=transform_res.session_id
        )

        return rehydrated_response
