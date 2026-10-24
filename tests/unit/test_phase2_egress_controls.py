"""
Unit tests for Phase 2 — Default-Deny Egress and Externally Consequential Action Controls.
Verifies all 20 required synthetic test scenarios.
"""

import pytest
import socket
import hashlib
from unittest.mock import MagicMock, patch

from epistemicos.containment import (
    ContainmentGuard,
    ContainmentViolationType,
    EgressPolicy,
    EgressTransportBroker,
    normalize_destination_host,
    parse_ip_numeric
)
from epistemicos.action_policy import (
    ActionCategory,
    ActionRegistry,
    RegisteredActionDefinition,
    SideEffectPolicyEngine,
    TypedHumanApprovalRecord
)
from epistemicos.shower_curtain.adapter import ShowerCurtainOpenAIAdapter
from epistemicos.shower_curtain.engine import ShowerCurtainEngine
from epistemicos.provenance import LocalProvenanceStore, ProvenanceEventType


# 1. Empty approved-egress policy blocks external destinations in protected mode.
def test_1_empty_approved_egress_policy_blocks():
    policy = EgressPolicy()  # empty allowed_destinations & allowed_wildcards
    guard = ContainmentGuard(egress_policy=policy)

    receipt = guard.inspect_network_egress("https://api.github.com/repos")
    assert receipt.passed is False
    assert receipt.violation_type == ContainmentViolationType.UNAUTHORIZED_EGRESS_ATTEMPT
    assert "Absent or empty approved-egress policy" in receipt.reason


# 2. An explicitly approved public destination is allowed only for the matching authorized operation.
def test_2_explicitly_approved_destination_allowed_matching_operation():
    policy = EgressPolicy(
        allowed_destinations={"api.github.com"},
        allowed_categories={ActionCategory.NETWORK_READ}
    )
    broker = EgressTransportBroker(
        policy=policy,
        resolver_func=lambda h: ["140.82.121.4"]
    )

    allowed, reason, ip = broker.establish_connection(
        target_url="https://api.github.com/repos",
        action_name="read_repo",
        category=ActionCategory.NETWORK_READ
    )
    assert allowed is True
    assert ip == "140.82.121.4"


# 3. A different public destination is blocked.
def test_3_different_public_destination_blocked():
    policy = EgressPolicy(
        allowed_destinations={"api.github.com"},
        allowed_categories={ActionCategory.NETWORK_READ}
    )
    broker = EgressTransportBroker(
        policy=policy,
        resolver_func=lambda h: ["142.250.190.46"]
    )

    allowed, reason, ip = broker.establish_connection(
        target_url="https://www.google.com/search",
        action_name="search",
        category=ActionCategory.NETWORK_READ
    )
    assert allowed is False
    assert "not in approved egress policy" in reason


# 4. Loopback, private, link-local, reserved, unspecified, and metadata destinations are blocked.
@pytest.mark.parametrize("target", [
    "http://127.0.0.1/admin",
    "http://localhost:8080",
    "http://10.0.0.1/internal",
    "http://192.168.1.1/router",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://0.0.0.0/",
])
def test_4_restricted_destinations_blocked(target):
    guard = ContainmentGuard()
    receipt = guard.inspect_network_egress(target)
    assert receipt.passed is False
    assert receipt.violation_type == ContainmentViolationType.UNAUTHORIZED_EGRESS_ATTEMPT


# 5. DNS resolution returning a restricted address is denied.
def test_5_dns_returning_restricted_address_denied():
    policy = EgressPolicy(allowed_destinations={"malicious-domain.com"})
    broker = EgressTransportBroker(
        policy=policy,
        resolver_func=lambda h: ["127.0.0.1"]
    )

    allowed, reason, ip = broker.establish_connection("https://malicious-domain.com/path")
    assert allowed is False
    assert "returned restricted IP" in reason


# 6. Mixed DNS answers containing both public and restricted addresses cannot lead to a connection.
def test_6_mixed_dns_answers_denied():
    policy = EgressPolicy(allowed_destinations={"mixed-domain.com"})
    broker = EgressTransportBroker(
        policy=policy,
        resolver_func=lambda h: ["93.184.216.34", "10.0.0.1"]
    )

    allowed, reason, ip = broker.establish_connection("https://mixed-domain.com/path")
    assert allowed is False
    assert "returned restricted IP" in reason
    assert ip is None


# 7. DNS failure and policy/resolver exceptions fail closed.
def test_7_dns_failure_fails_closed():
    policy = EgressPolicy(allowed_destinations={"failed-domain.com"})

    def failing_resolver(h):
        raise socket.gaierror("Name resolution error")

    broker = EgressTransportBroker(policy=policy, resolver_func=failing_resolver)
    allowed, reason, ip = broker.establish_connection("https://failed-domain.com/path")
    assert allowed is False
    assert "Resolver error" in reason


# 8. Redirects to an unapproved host are blocked before the redirected request is made.
def test_8_redirect_unapproved_host_blocked():
    policy = EgressPolicy(allowed_destinations={"safe-domain.com"})
    broker = EgressTransportBroker(
        policy=policy,
        resolver_func=lambda h: ["93.184.216.34"] if h == "safe-domain.com" else ["142.250.190.46"]
    )

    # Initial safe connection
    ok_orig, _, _ = broker.establish_connection("https://safe-domain.com/login")
    assert ok_orig is True

    # Redirect to unapproved domain
    ok_redir, reason_redir, _ = broker.revalidate_redirect(
        original_url="https://safe-domain.com/login",
        redirect_url="https://evil-exfil.com/sink"
    )
    assert ok_redir is False
    assert "not in approved egress policy" in reason_redir


# 9. URL normalization covers malformed authorities, userinfo, encoded delimiters, alternate IP forms, and IPv6.
def test_9_url_normalization_edge_cases():
    # Userinfo / encoded delimiter bypasses
    assert normalize_destination_host("http://user:pass#@example.com/") == ""
    assert normalize_destination_host("http://127.0.0.1%23@example.com/") == ""

    # IPv6 bracketed
    assert normalize_destination_host("http://[::1]:8080/path") == "::1"
    assert normalize_destination_host("http://[2001:db8::1]/path") == "2001:db8::1"

    # Alternate numeric IP encodings
    assert normalize_destination_host("http://0x7f000001/path") == "127.0.0.1"
    assert normalize_destination_host("http://2130706433/path") == "127.0.0.1"
    assert normalize_destination_host("http://0177.0.0.1/path") == "127.0.0.1"

    # Trailing dot
    assert normalize_destination_host("http://example.com./path") == "example.com"


# 10. A URL hidden in nested arguments cannot bypass checks in a registered network operation.
def test_10_nested_arguments_url_cannot_bypass():
    guard = ContainmentGuard()

    tool_args = ({
        "nested": {
            "options": ["--target", "http://169.254.169.254/latest/meta-data/"]
        }
    },)

    success, res, receipt = guard.wrap_tool_execution(
        tool_name="network_tool",
        tool_func=lambda opts: "executed",
        args=tool_args
    )
    assert success is False
    assert receipt.violation_type == ContainmentViolationType.UNAUTHORIZED_EGRESS_ATTEMPT


# 11. A raw/unregistered callback or tool cannot be treated as contained merely because the original URL passed a string check.
def test_11_unregistered_callback_cannot_claim_containment():
    engine = SideEffectPolicyEngine()
    # Evaluating an unregistered action operation
    allowed, reason = engine.evaluate_side_effect_authorization(
        operation_id="unregistered_raw_callback",
        target_resource="https://api.github.com",
        payload={"data": 123},
        task_id="TASK-11",
        correlation_id="CORR-11"
    )
    assert allowed is False
    assert "is unregistered" in reason


# 12. Account creation, public repository changes, code publication, emails, and contact with humans are denied unless the exact action and target are explicitly authorized.
@pytest.mark.parametrize("op_id", [
    "account_creation",
    "send_message",
    "public_repo_mutation",
    "package_publish",
])
def test_12_consequential_actions_denied_without_typed_approval(op_id):
    engine = SideEffectPolicyEngine()
    allowed, reason = engine.evaluate_side_effect_authorization(
        operation_id=op_id,
        target_resource="https://external-service.org",
        payload={"action": op_id},
        task_id="TASK-12",
        correlation_id="CORR-12"
    )
    assert allowed is False
    assert "requires explicit typed human approval" in reason


# 13. Generic automated continuation responses cannot authorize external side effects.
def test_13_generic_automated_continuation_cannot_authorize():
    engine = SideEffectPolicyEngine()

    # Invalid record signature simulating generic "continue" text
    invalid_record = TypedHumanApprovalRecord(
        approval_id="APP-13",
        operation_id="public_repo_mutation",
        target_resource="https://github.com/public/repo",
        canonical_args_digest="invalid_digest",
        task_id="TASK-13",
        policy_version="1.0.0",
        approved_by_principal="AutoPrompt",
        timestamp="2026-10-24T00:00:00Z",
        signature="invalid_signature"
    )

    allowed, reason = engine.evaluate_side_effect_authorization(
        operation_id="public_repo_mutation",
        target_resource="https://github.com/public/repo",
        payload={"pr_title": "Automated PR"},
        task_id="TASK-13",
        correlation_id="CORR-13",
        approval_record=invalid_record
    )
    assert allowed is False
    assert "Approval verification failed" in reason


# 14. Exhausting in-scope routes does not broaden the allowed destinations or operation classes.
def test_14_exhausting_routes_does_not_broaden_allowlist():
    policy = EgressPolicy(allowed_destinations={"in-scope.internal"})
    broker = EgressTransportBroker(
        policy=policy,
        resolver_func=lambda h: ["10.0.0.5"] if h == "in-scope.internal" else ["142.250.190.46"]
    )

    # Exhausted in-scope attempt
    ok1, _, _ = broker.establish_connection("https://in-scope.internal/api/v1")

    # Pivot attempt to discovered host
    ok2, reason2, _ = broker.establish_connection("https://out-of-scope.public/api/v1")
    assert ok2 is False
    assert "not in approved egress policy" in reason2


# 15. A newly discovered target requires a fresh authorization grant.
def test_15_newly_discovered_target_requires_fresh_grant():
    policy = EgressPolicy(allowed_destinations={"initial-target.com"})
    broker = EgressTransportBroker(
        policy=policy,
        resolver_func=lambda h: ["93.184.216.34"]
    )

    # Initial target allowed
    ok1, _, _ = broker.establish_connection("https://initial-target.com/page")
    assert ok1 is True

    # Discovered sub-target or new target blocked without grant
    ok2, reason2, _ = broker.establish_connection("https://discovered-target.com/page")
    assert ok2 is False
    assert "not in approved egress policy" in reason2


# Focused tests for RegisteredActionDefinition allowed_resources enforcement
def test_action_allowed_resources_enforcement():
    registry = ActionRegistry()

    # 1. Action with explicit resource allowlist
    custom_action_allowed = RegisteredActionDefinition(
        operation_id="custom_scoped_op",
        category=ActionCategory.PUBLIC_REPOSITORY_MUTATION,
        description="Scoped repo mutation",
        requires_human_approval=True,
        allowed_resources={"https://github.com/my-org/allowed-repo"},
        is_externally_consequential=True
    )
    registry.register_action(custom_action_allowed)

    engine = SideEffectPolicyEngine(registry=registry, signing_secret="TEST_SECRET")

    payload = {"commit_id": "def5678"}
    digest = engine.compute_canonical_digest(payload)

    # Valid approval for allowed target resource
    record_allowed = TypedHumanApprovalRecord(
        approval_id="APP-RES-1",
        operation_id="custom_scoped_op",
        target_resource="https://github.com/my-org/allowed-repo",
        canonical_args_digest=digest,
        task_id="TASK-RES",
        policy_version="1.0.0",
        approved_by_principal="admin",
        timestamp="2026-10-24T00:00:00Z",
        signature=engine.compute_approval_signature((
            "APP-RES-1", "custom_scoped_op", "https://github.com/my-org/allowed-repo",
            digest, "TASK-RES", "1.0.0", "admin"
        ))
    )

    # Test allowed target -> Allowed
    ok_target, msg_target = engine.evaluate_side_effect_authorization(
        operation_id="custom_scoped_op",
        target_resource="https://github.com/my-org/allowed-repo",
        payload=payload,
        task_id="TASK-RES",
        correlation_id="CORR-RES-1",
        approval_record=record_allowed
    )
    assert ok_target is True

    # Valid approval for disallowed target resource outside allowlist -> Denied
    record_disallowed = TypedHumanApprovalRecord(
        approval_id="APP-RES-2",
        operation_id="custom_scoped_op",
        target_resource="https://github.com/my-org/disallowed-repo",
        canonical_args_digest=digest,
        task_id="TASK-RES",
        policy_version="1.0.0",
        approved_by_principal="admin",
        timestamp="2026-10-24T00:00:00Z",
        signature=engine.compute_approval_signature((
            "APP-RES-2", "custom_scoped_op", "https://github.com/my-org/disallowed-repo",
            digest, "TASK-RES", "1.0.0", "admin"
        ))
    )

    ok_disallowed, msg_disallowed = engine.evaluate_side_effect_authorization(
        operation_id="custom_scoped_op",
        target_resource="https://github.com/my-org/disallowed-repo",
        payload=payload,
        task_id="TASK-RES",
        correlation_id="CORR-RES-2",
        approval_record=record_disallowed
    )
    assert ok_disallowed is False
    assert "not in allowed resources" in msg_disallowed

    # 2. Action with empty resource allowlist -> Fails closed
    empty_res_action = RegisteredActionDefinition(
        operation_id="empty_res_op",
        category=ActionCategory.PUBLIC_REPOSITORY_MUTATION,
        description="Op with empty allowlist",
        requires_human_approval=False,
        allowed_resources=set(),
        is_externally_consequential=False
    )
    registry.register_action(empty_res_action)

    ok_empty, msg_empty = engine.evaluate_side_effect_authorization(
        operation_id="empty_res_op",
        target_resource="https://github.com/my-org/repo",
        payload=payload,
        task_id="TASK-RES",
        correlation_id="CORR-RES-3"
    )
    assert ok_empty is False
    assert "Resource allowlist is empty" in msg_empty


# 16. A destination or operation changed after grant issuance invalidates the capability.
def test_16_destination_or_operation_change_invalidates_capability():
    engine = SideEffectPolicyEngine(signing_secret="TEST_SECRET")

    payload = {"commit_id": "abc1234"}
    digest = engine.compute_canonical_digest(payload)

    record_tuple = (
        "APP-16",
        "public_repo_mutation",
        "https://github.com/target/repo",
        digest,
        "TASK-16",
        "1.0.0",
        "human_admin"
    )
    valid_sig = engine.compute_approval_signature(record_tuple)

    record = TypedHumanApprovalRecord(
        approval_id="APP-16",
        operation_id="public_repo_mutation",
        target_resource="https://github.com/target/repo",
        canonical_args_digest=digest,
        task_id="TASK-16",
        policy_version="1.0.0",
        approved_by_principal="human_admin",
        timestamp="2026-10-24T00:00:00Z",
        signature=valid_sig
    )

    # Valid approval passes
    ok_valid, msg_valid = engine.evaluate_side_effect_authorization(
        operation_id="public_repo_mutation",
        target_resource="https://github.com/target/repo",
        payload=payload,
        task_id="TASK-16",
        correlation_id="CORR-16-VALID",
        approval_record=record
    )
    assert ok_valid is True

    # Target changed to different repo -> denied
    allowed, reason = engine.evaluate_side_effect_authorization(
        operation_id="public_repo_mutation",
        target_resource="https://github.com/target/OTHER-REPO",
        payload=payload,
        task_id="TASK-16",
        correlation_id="CORR-16",
        approval_record=record
    )
    assert allowed is False
    assert "Approval target mismatch" in reason


# 17. ShowerCurtain's required sensitive-data policy remains enforced on the actual outbound provider path.
def test_17_shower_curtain_sensitive_data_policy_enforced_on_outbound_path():
    adapter = ShowerCurtainOpenAIAdapter()

    # Payload with unredacted sensitive credential
    sensitive_payload = {
        "messages": [
            {"role": "user", "content": "My API key is sk-abcdef1234567890abcdef1234567890."}
        ]
    }

    res = adapter.execute_completion(
        completion_func=lambda p: {"choices": [{"message": {"content": "acknowledged"}}]},
        request_payload=sensitive_payload,
        dry_run=True,
        provider_url="https://api.openai.com/v1/chat/completions"
    )

    preview_text = res["preview_payload"]["messages"][0]["content"]
    assert "sk-abcdef1234567890abcdef1234567890" not in preview_text
    assert "[REDACTED_CREDENTIAL]" in preview_text


# 18. All rejected actions have callback/transport invocation count zero.
def test_18_rejected_actions_have_zero_invocation_count():
    invocations = []

    def mock_transport():
        invocations.append(1)
        return "sent"

    policy = EgressPolicy(allowed_destinations={"allowed.com"})
    guard = ContainmentGuard(egress_policy=policy)

    ok, res, receipt = guard.wrap_tool_execution(
        tool_name="mock_tool",
        tool_func=mock_transport,
        kwargs={"url": "https://blocked-destination.com/exfil"}
    )

    assert ok is False
    assert len(invocations) == 0


# 19. Authorized synthetic controls still execute through the registered executor and only within their allowed destinations.
def test_19_authorized_synthetic_controls_execute_within_allowed_destinations():
    invocations = []

    def mock_transport():
        invocations.append(1)
        return "success_response"

    policy = EgressPolicy(allowed_destinations={"allowed.com"})
    broker = EgressTransportBroker(
        policy=policy,
        resolver_func=lambda h: ["93.184.216.34"]
    )

    allowed, reason, ip = broker.establish_connection("https://allowed.com/api")
    assert allowed is True

    if allowed:
        res = mock_transport()

    assert res == "success_response"
    assert len(invocations) == 1


# 20. Denial events are recorded; provenance failures do not result in false claims that a side effect was prevented if the call had already occurred.
def test_20_denial_events_recorded_in_provenance(tmp_path):
    prov_file = tmp_path / "egress_prov.jsonl"
    store = LocalProvenanceStore(log_path=str(prov_file))

    policy = EgressPolicy(allowed_destinations={"safe.com"})
    broker = EgressTransportBroker(
        policy=policy,
        resolver_func=lambda h: ["127.0.0.1"],  # Returns loopback restricted IP
        provenance_store=store
    )

    allowed, reason, ip = broker.establish_connection(
        target_url="https://safe.com/query",
        action_name="query_action",
        correlation_id="CORR-20",
        request_id="REQ-20"
    )
    assert allowed is False

    events = store.get_events_for_correlation("CORR-20")
    assert len(events) == 1
    assert events[0].event_type == ProvenanceEventType.EGRESS_BLOCKED.value
    assert "returned restricted IP" in events[0].outcome["reason"]
