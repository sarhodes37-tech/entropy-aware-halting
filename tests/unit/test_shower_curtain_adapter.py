"""
Unit Tests for ShowerCurtainOpenAIAdapter.

Verifies provider adapter initialization, outbound privacy transformation,
egress gate enforcement, dry-run suppression, and inbound rehydration.
"""

from unittest.mock import MagicMock
import pytest

from epistemicos.shower_curtain.adapter import ShowerCurtainOpenAIAdapter
from epistemicos.shower_curtain.engine import ShowerCurtainEngine, PrivacyTransformationResult
from epistemicos.shower_curtain.gate import ShowerCurtainGate
from epistemicos.gates import GateAction, GateResult


def test_adapter_default_initialization():
    """Verifies adapter initializes default ShowerCurtainEngine when none is provided."""
    adapter = ShowerCurtainOpenAIAdapter()
    assert adapter.engine is not None
    assert isinstance(adapter.engine, ShowerCurtainEngine)


def test_adapter_custom_engine_initialization():
    """Verifies adapter accepts a custom engine instance."""
    custom_engine = ShowerCurtainEngine()
    adapter = ShowerCurtainOpenAIAdapter(engine=custom_engine)
    assert adapter.engine is custom_engine


def test_execute_completion_happy_path():
    """Verifies normal outbound transformation, provider call, and inbound rehydration."""
    adapter = ShowerCurtainOpenAIAdapter()
    received_payloads = []

    def mock_completion(payload):
        received_payloads.append(payload)
        return {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "Message acknowledged for EMAIL_1@sanitized.local."
                    }
                }
            ]
        }

    request = {
        "messages": [
            {"role": "user", "content": "My email address is alice@example.com."}
        ]
    }

    response = adapter.execute_completion(
        completion_func=mock_completion,
        request_payload=request,
        session_id="sess_adapter_happy"
    )

    # 1. Completion function received sanitized payload
    assert len(received_payloads) == 1
    sanitized_prompt = received_payloads[0]["messages"][0]["content"]
    assert "alice@example.com" not in sanitized_prompt
    assert "EMAIL_1" in sanitized_prompt or "sanitized.local" in sanitized_prompt

    # 2. Response was rehydrated with original secret
    rehydrated_content = response["choices"][0]["message"]["content"]
    assert "alice@example.com" in rehydrated_content


def test_execute_completion_dry_run_mode():
    """Verifies that dry_run=True suppresses remote provider call and returns preview report."""
    adapter = ShowerCurtainOpenAIAdapter()
    provider_called = False

    def mock_completion(payload):
        nonlocal provider_called
        provider_called = True
        return {"choices": []}

    request = {"prompt": "User Alice with email alice@example.com."}

    result = adapter.execute_completion(
        completion_func=mock_completion,
        request_payload=request,
        session_id="sess_adapter_dry_run",
        dry_run=True
    )

    assert provider_called is False
    assert result["dry_run"] is True
    assert "sanitized_payload" in result
    assert "preview_payload" in result
    assert "transformation_report" in result


def test_execute_completion_egress_gate_denial():
    """Verifies PermissionError when egress gate denies the request."""
    class AlwaysDenyGate(ShowerCurtainGate):
        def evaluate(self, payload, context):
            return GateResult(
                action=GateAction.HALT,
                reason="Denied due to policy violation"
            )

    blocking_engine = ShowerCurtainEngine(egress_gate=AlwaysDenyGate())
    adapter = ShowerCurtainOpenAIAdapter(engine=blocking_engine)
    provider_called = False

    def mock_completion(payload):
        nonlocal provider_called
        provider_called = True
        return {}

    request = {"prompt": "Some sensitive content"}

    with pytest.raises(PermissionError) as exc_info:
        adapter.execute_completion(
            completion_func=mock_completion,
            request_payload=request,
            session_id="sess_adapter_denied"
        )

    assert "Shower Curtain Egress Gate Denied Request: Denied due to policy violation" in str(exc_info.value)
    assert provider_called is False


def test_execute_completion_session_id_propagation():
    """Verifies session_id is properly passed down to transformation and process_response."""
    mock_engine = MagicMock(spec=ShowerCurtainEngine)

    mock_gate_result = GateResult(action=GateAction.ALLOW, reason="Allowed")
    mock_transform_res = PrivacyTransformationResult(
        original_payload={"prompt": "raw prompt"},
        sanitized_payload={"prompt": "sanitized prompt"},
        session_id="sess_custom_123",
        transaction_id="tx_123",
        detections=[],
        decisions=[],
        mpu_result=None,
        gate_result=mock_gate_result,
        preview_payload={"prompt": "preview prompt"}
    )

    mock_engine.transform_request.return_value = mock_transform_res
    mock_engine.process_response.return_value = {"choices": [{"text": "rehydrated response"}]}

    adapter = ShowerCurtainOpenAIAdapter(engine=mock_engine)

    def mock_completion(payload):
        return {"choices": [{"text": "raw response"}]}

    res = adapter.execute_completion(
        completion_func=mock_completion,
        request_payload={"prompt": "raw prompt"},
        session_id="sess_custom_123"
    )

    mock_engine.transform_request.assert_called_once_with(
        payload={"prompt": "raw prompt"},
        session_id="sess_custom_123",
        dry_run=False
    )
    mock_engine.process_response.assert_called_once_with(
        response_payload={"choices": [{"text": "raw response"}]},
        session_id="sess_custom_123"
    )
    assert res == {"choices": [{"text": "rehydrated response"}]}
