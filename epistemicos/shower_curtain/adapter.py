"""
Provider Adapter Interface for Shower Curtain.

Demonstrates an OpenAI-compatible / generic LLM provider middleware adapter
wrapping model calls with outbound privacy transformations and inbound rehydration.
"""

from typing import Dict, Any, Callable, Optional
from epistemicos.shower_curtain.engine import ShowerCurtainEngine, PrivacyTransformationResult
from epistemicos.gates import GateAction


class ShowerCurtainOpenAIAdapter:
    """
    OpenAI-compatible / generic provider middleware adapter.
    """

    def __init__(self, engine: Optional[ShowerCurtainEngine] = None):
        self.engine = engine or ShowerCurtainEngine()

    def execute_completion(
        self,
        completion_func: Callable[[Dict[str, Any]], Dict[str, Any]],
        request_payload: Dict[str, Any],
        session_id: Optional[str] = None,
        dry_run: bool = False
    ) -> Dict[str, Any]:
        # 1. Outbound transformation
        transform_res: PrivacyTransformationResult = self.engine.transform_request(
            payload=request_payload,
            session_id=session_id,
            dry_run=dry_run
        )

        # 2. Check Egress Gate
        if transform_res.gate_result.action != GateAction.ALLOW:
            raise PermissionError(
                f"Shower Curtain Egress Gate Denied Request: {transform_res.gate_result.reason}"
            )

        # 3. Handle Dry Run
        if dry_run:
            return {
                "dry_run": True,
                "sanitized_payload": transform_res.sanitized_payload,
                "transformation_report": transform_res.to_dict()
            }

        # 4. Invoke Remote Provider with Sanitized Payload
        raw_response = completion_func(transform_res.sanitized_payload)

        # 5. Inbound Response Processing & Controlled Rehydration
        rehydrated_response = self.engine.process_response(
            response_payload=raw_response,
            session_id=transform_res.session_id
        )

        return rehydrated_response
