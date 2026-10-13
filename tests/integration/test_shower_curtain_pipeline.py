"""
Integration Pipeline Tests for Shower Curtain Privacy Subsystem.
"""

import pytest
import os
import tempfile
from epistemicos.core import EpistemicOrchestrator
from epistemicos.shower_curtain import ShowerCurtainEngine, ShowerCurtainOpenAIAdapter
from epistemicos.gates import GateAction


def test_orchestrator_shower_curtain_integration():
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
        log_path = tmp.name

    orchestrator = EpistemicOrchestrator(audit_log_path=log_path)

    # First run payload through Shower Curtain engine to sanitize outbound text
    raw_payload = {
        "policy_id": "POL-2026-TEST",
        "primary_metric": 100.0,
        "raw_payload": {
            "prompt": "Customer email is alice@example.com"
        }
    }

    sanitized_res = orchestrator.shower_curtain.transform_request(raw_payload)
    context = {"token_count": 10, "shower_curtain_exception_authorized": True}

    res = orchestrator.process_submission(sanitized_res.sanitized_payload, context)

    assert res["status"] == "ALLOWED"
    if os.path.exists(log_path):
        os.remove(log_path)


def test_full_pipeline_roundtrip():
    engine = ShowerCurtainEngine()
    adapter = ShowerCurtainOpenAIAdapter(engine=engine)

    def fake_llm(payload):
        user_msg = payload["messages"][0]["content"]
        # Remote model sees sanitized email
        assert "alice@example.com" not in user_msg
        assert "EMAIL_1@sanitized.local" in user_msg
        return {
            "choices": [{"message": {"content": "Sending confirmation to EMAIL_1@sanitized.local"}}]
        }

    request = {"messages": [{"role": "user", "content": "Please email alice@example.com."}]}
    res = adapter.execute_completion(fake_llm, request)

    output = res["choices"][0]["message"]["content"]
    # Local client gets rehydrated output
    assert "alice@example.com" in output
