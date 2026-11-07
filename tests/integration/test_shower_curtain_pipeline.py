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


def test_orchestration_configured_token_threat_model_integration():
    """
    Evaluates configured-token threat model through real orchestration entry point
    (process_submission -> _execute_pipeline -> _evaluate_gates -> ShowerCurtainGate).
    Demonstrates architectural weakness: context is caller-supplied bearer dictionary;
    any caller with knowledge of the configured secret can inject it and authorize PII egress.
    Guarantees cleanup of temporary audit files even if assertions fail.
    """
    from epistemicos.shower_curtain.gate import ShowerCurtainGate
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
        log_path = tmp.name

    try:
        orchestrator = EpistemicOrchestrator(audit_log_path=log_path)
        # Register ShowerCurtainGate with a valid configured secret token
        configured_gate = ShowerCurtainGate(trusted_exception_token="INTEGRATION_TRUSTED_SECRET")
        orchestrator.register_gate(configured_gate)

        raw_payload_pii = {
            "policy_id": "POL-2026-PII",
            "primary_metric": 50.0,
            "raw_payload": {
                "customer_email": "alice@example.com"
            }
        }

        # 1. Untrusted caller supplying arbitrary incorrect token -> MUST HALT
        res_arbitrary = orchestrator.process_submission(
            raw_payload=raw_payload_pii,
            context={"shower_curtain_exception_token": "ARBITRARY_ATTACKER_TOKEN"}
        )
        assert res_arbitrary["status"] == "HALTED"
        assert res_arbitrary["gate"] == "ShowerCurtainGate"

        # 2. Untrusted caller injecting the correct secret token
        res_injected = orchestrator.process_submission(
            raw_payload=raw_payload_pii,
            context={"shower_curtain_exception_token": "INTEGRATION_TRUSTED_SECRET"}
        )
        # Non-credential PII authorized; gate accepts bearer token without origin checks
        assert res_injected["status"] == "ALLOWED"

        # 3. Credential-bearing payload even when valid token is supplied -> MUST HALT
        raw_payload_cred = {
            "policy_id": "POL-2026-CRED",
            "primary_metric": 50.0,
            "raw_payload": {
                "api_key": "sk-proj1234567890abcdef1234567890"
            }
        }
        res_cred = orchestrator.process_submission(
            raw_payload=raw_payload_cred,
            context={"shower_curtain_exception_token": "INTEGRATION_TRUSTED_SECRET"}
        )
        assert res_cred["status"] == "HALTED"
        assert "Credentials cannot bypass mandatory privacy protection" in res_cred["reason"]
    finally:
        if os.path.exists(log_path):
            os.remove(log_path)
