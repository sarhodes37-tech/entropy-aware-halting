import errno
import ipaddress
import socket
from unittest.mock import MagicMock, patch

import pytest

from epistemicos.action_policy import ActionCategory
from epistemicos.containment import (
    ContainmentGuard,
    ContainmentViolationType,
    ControlledEgressTransport,
    EgressPolicy,
    EgressTransportBroker,
    PinnedHTTPConnection,
    PinnedHTTPSConnection,
    extract_url_components,
    parse_ip_numeric,
    parse_url_authority_structure,
)
from epistemicos.gates import GateDecision, GateInput, GateOutcome
from epistemicos.provenance import LocalProvenanceStore


class TestContainmentGuardEvaluateContract:
    """Tests for ContainmentGuard.evaluate_contract (lines 513-557)."""

    def test_evaluate_contract_clean_payload_allows(self):
        guard = ContainmentGuard()
        gate_input = GateInput(
            payload={"query": "SELECT count(*) FROM users WHERE status = 'active'"},
            context={"correlation_id": "test-corr-1", "original_goal": "Run diagnostic query"}
        )
        outcome = guard.evaluate_contract(gate_input)
        assert isinstance(outcome, GateOutcome)
        assert outcome.decision == GateDecision.ALLOW
        assert outcome.reason_code == "CONTAINMENT_GUARDRAILS_PASSED"
        assert outcome.gate_name == guard.gate_name
        assert outcome.latency_ms >= 0.0

    def test_evaluate_contract_forbidden_command_halts(self):
        guard = ContainmentGuard()
        gate_input = GateInput(
            payload={"action": "run_shell", "cmd": "rm -rf / --no-preserve-root"},
            context={"correlation_id": "test-corr-2"}
        )
        outcome = guard.evaluate_contract(gate_input)
        assert outcome.decision == GateDecision.HALT
        assert "Command execution blocked" in outcome.reason_code
        assert outcome.evidence["status"] == "HALTED"
        assert outcome.evidence["vectors_revoked"] == 1

    def test_evaluate_contract_goal_integrity_violation_in_context_halts(self):
        guard = ContainmentGuard()
        gate_input = GateInput(
            payload={"action": "pytest", "args": "tests/test_model.py; assert True"},
            context={"correlation_id": "test-corr-3", "original_goal": "Verify all unit tests pass"}
        )
        outcome = guard.evaluate_contract(gate_input)
        assert outcome.decision == GateDecision.HALT
        assert "Reward-cheating attempt detected" in outcome.reason_code
        assert outcome.evidence["status"] == "HALTED"
        assert outcome.evidence["vectors_revoked"] == 1

    def test_evaluate_contract_goal_integrity_violation_in_payload_dict_halts(self):
        guard = ContainmentGuard()
        gate_input = GateInput(
            payload={"original_goal": "Run audit", "notes": "return True # skip test"},
            context={"correlation_id": "test-corr-4"}
        )
        outcome = guard.evaluate_contract(gate_input)
        assert outcome.decision == GateDecision.HALT
        assert "Reward-cheating attempt detected" in outcome.reason_code
        assert outcome.evidence["status"] == "HALTED"

    def test_evaluate_contract_unauthorized_network_egress_halts(self):
        guard = ContainmentGuard(
            egress_policy=EgressPolicy(allowed_destinations=["api.github.com"])
        )
        gate_input = GateInput(
            payload={"target_url": "https://malicious-exfil.com/data"},
            context={"correlation_id": "test-corr-5"}
        )
        outcome = guard.evaluate_contract(gate_input)
        assert outcome.decision == GateDecision.HALT
        assert "Egress blocked" in outcome.reason_code
        assert outcome.evidence["status"] == "HALTED"
        assert outcome.evidence["vectors_revoked"] == 1


class TestContainmentInputValidationAndParsing:
    """Tests for edge cases in url and destination parsing."""

    def test_extract_url_components_https_default_port(self):
        proto, port = extract_url_components(
            "https://api.github.com/v1", default_protocol="http", default_port=80
        )
        assert proto == "https"
        assert port == 443

    def test_parse_url_authority_structure_fragment_in_unquoted_netloc(self):
        res = parse_url_authority_structure("http://attacker.com%23@legit.com/")
        assert res["valid"] is False
        assert res["normalized_host"] == ""

    def test_parse_url_authority_structure_whitespace_padded_host(self):
        res = parse_url_authority_structure("http://example.com /path")
        assert res["valid"] is False

    def test_parse_url_authority_structure_empty_or_all_spaces_host(self):
        res = parse_url_authority_structure("http://[::1]%20/path")
        assert res["valid"] is False

    def test_parse_url_authority_structure_ipv6_bracket_invalid_ip(self):
        res = parse_url_authority_structure("[invalid-ipv6-literal]")
        assert res["valid"] is False
        assert res["normalized_host"] == ""

    def test_parse_url_authority_structure_ipv4_mapped_in_clean_host(self):
        res = parse_url_authority_structure("http://::ffff:192.0.2.1/")
        assert res["valid"] is True
        assert res["normalized_host"] == "192.0.2.1"

    def test_parse_url_authority_structure_idna_decode_error(self):
        res = parse_url_authority_structure("http://\uffff.com")
        assert res["valid"] is False

    def test_parse_ip_numeric_limits(self):
        assert parse_ip_numeric("0" * 35) is None

        long_part_ip = "127." + ("0" * 18) + ".0.1"
        assert parse_ip_numeric(long_part_ip) is None

    def test_parse_ip_numeric_hex_octal_and_dotted(self):
        ip_hex = parse_ip_numeric("0x7f000001")
        assert ip_hex == ipaddress.IPv4Address("127.0.0.1")

        ip_oct = parse_ip_numeric("017700000001")
        assert ip_oct == ipaddress.IPv4Address("127.0.0.1")

        assert parse_ip_numeric("0x100000000") is None
        assert parse_ip_numeric("040000000000") is None

        ip_dotted = parse_ip_numeric("0177.0.0.1")
        assert ip_dotted == ipaddress.IPv4Address("127.0.0.1")

        assert parse_ip_numeric("0177.0.0.999") is None

        # Fallback multi-part parser when socket.inet_aton fails (lines 409-412)
        with patch("socket.inet_aton", side_effect=OSError("Platform inet_aton limitation")):
            assert parse_ip_numeric("0177.0.0.1") == ipaddress.IPv4Address("127.0.0.1")
            assert parse_ip_numeric("0x7f.0.0.1") == ipaddress.IPv4Address("127.0.0.1")
            assert parse_ip_numeric("0177.0.0.999") is None
            assert parse_ip_numeric("0177.0.0") is None


class TestContainmentEgressAuthorizationAndRejections:
    """Tests for egress authorization, restricted IP classification, and destination evaluation."""

    def test_safe_dns_resolution_restricted_mapped_and_special_ranges(self):
        guard = ContainmentGuard()

        with guard._safe_dns_resolution():
            fake_addr = [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::ffff:127.0.0.1", 80))]
            with patch("epistemicos.containment._original_getaddrinfo", return_value=fake_addr):
                with pytest.raises(socket.error, match="returned restricted IP"):
                    socket.getaddrinfo("mapped.local", 80)

        with guard._safe_dns_resolution():
            fake_loop = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))]
            with patch("epistemicos.containment._original_getaddrinfo", return_value=fake_loop):
                with pytest.raises(socket.error, match="returned restricted IP"):
                    socket.getaddrinfo("loopback.local", 80)

        for bad_ip in ["169.254.1.1", "240.0.0.1", "0.0.0.0"]:
            with guard._safe_dns_resolution():
                fake_res = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (bad_ip, 80))]
                with patch("epistemicos.containment._original_getaddrinfo", return_value=fake_res):
                    with pytest.raises(socket.error, match="returned restricted IP"):
                        socket.getaddrinfo("special.local", 80)

    def test_egress_policy_action_category_and_protocol_rejection(self):
        policy = EgressPolicy(
            allowed_destinations=["api.github.com"],
            allowed_categories={ActionCategory.NETWORK_READ},
            allowed_protocols={"https"}
        )

        allowed, msg = policy.is_destination_allowed(
            "api.github.com",
            category=ActionCategory.STATE_MUTATION
        )
        assert allowed is False
        assert "Action category 'STATE_MUTATION' is not authorized" in msg

        allowed, msg = policy.is_destination_allowed("ftp://api.github.com")
        assert allowed is False
        assert "Protocol 'ftp' is not authorized" in msg

    def test_egress_policy_wildcard_domain_matching(self):
        policy = EgressPolicy(
            allowed_wildcards=["*.api.github.com"]
        )
        allowed, msg = policy.is_destination_allowed("v1.api.github.com")
        assert allowed is True
        assert "Allowed by wildcard match" in msg

        allowed, msg = policy.is_destination_allowed("api.github.com")
        assert allowed is False

    def test_is_restricted_target_edge_cases(self):
        guard = ContainmentGuard()

        assert guard._is_restricted_target("") is True
        assert guard._is_restricted_target("   ") is True

        assert guard._is_restricted_target("::ffff:127.0.0.1") is True
        assert guard._is_restricted_target("::ffff:93.184.216.34") is False

        with patch("socket.getaddrinfo", return_value=[]):
            assert guard._is_restricted_target("nonexistent.service.local") is True

        fake_mapped = [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::ffff:127.0.0.1", 80))]
        with patch("socket.getaddrinfo", return_value=fake_mapped):
            assert guard._is_restricted_target("mapped.test") is True

    def test_inspect_network_egress_allowed_domains_whitelist_rejection(self):
        guard = ContainmentGuard()
        guard.egress_policy = None
        guard.allowed_domains = {"trusted.internal.org"}
        with patch.object(guard, "_is_restricted_target", return_value=False):
            receipt = guard.inspect_network_egress("https://api.github.com/data")
            assert receipt.passed is False
            assert receipt.violation_type == ContainmentViolationType.UNAUTHORIZED_EGRESS_ATTEMPT
            assert "is not in allowed domain whitelist" in receipt.reason

    def test_is_candidate_destination_edge_cases(self):
        assert ContainmentGuard._is_candidate_destination(None) is False
        assert ContainmentGuard._is_candidate_destination(12345) is False

        assert ContainmentGuard._is_candidate_destination("   ") is False

        assert ContainmentGuard._is_candidate_destination("0x7f000001") is True

        assert ContainmentGuard._is_candidate_destination("myservice.org") is True
        assert ContainmentGuard._is_candidate_destination("script.py") is False
        assert ContainmentGuard._is_candidate_destination("data.json") is False
        assert ContainmentGuard._is_candidate_destination("document.pdf") is False


class TestEgressTransportBrokerAndSockets:
    """Tests for EgressTransportBroker and socket patching."""

    def test_broker_init_infrastructure_enforcement_missing_raises(self):
        with pytest.raises(
            RuntimeError,
            match="Mandatory infrastructure-level network enforcement is missing"
        ):
            EgressTransportBroker(
                policy=EgressPolicy(),
                require_infrastructure_enforcement=True,
                infrastructure_enforced=False
            )

    def test_broker_resolve_host_ipv4_mapped(self):
        broker = EgressTransportBroker(policy=EgressPolicy())
        ips = broker._default_resolver("::ffff:192.0.2.1")
        assert ips == ["192.0.2.1"]

    def test_broker_record_egress_event_store_exception_swallowed(self):
        mock_store = MagicMock(spec=LocalProvenanceStore)
        mock_store.record_event.side_effect = OSError("Disk full")

        broker = EgressTransportBroker(
            policy=EgressPolicy(allowed_destinations=["api.github.com"]),
            provenance_store=mock_store
        )
        broker._record_egress_event(
            correlation_id="corr-1",
            request_id="req-1",
            action_name="network_get",
            target_url="https://api.github.com",
            normalized_host="api.github.com",
            resolved_ip="140.82.121.4",
            allowed=False,
            reason="Blocked"
        )
        mock_store.record_event.assert_called_once()

    def test_broker_establish_connection_invalid_host(self):
        broker = EgressTransportBroker(policy=EgressPolicy())
        success, reason, ip = broker.establish_connection(
            "   ", correlation_id="c1", request_id="r1"
        )
        assert success is False
        assert "Missing or invalid target destination" in reason
        assert ip is None

    def test_broker_establish_connection_zero_ips_resolved(self):
        broker = EgressTransportBroker(
            policy=EgressPolicy(allowed_destinations=["valid.host"]),
            resolver_func=lambda h: []
        )
        success, reason, ip = broker.establish_connection(
            "https://valid.host", correlation_id="c1", request_id="r1"
        )
        assert success is False
        assert "Resolver returned zero IP addresses" in reason
        assert ip is None

    def test_broker_establish_connection_restricted_mapped_link_local_and_invalid_ips(self):
        broker_mapped = EgressTransportBroker(
            policy=EgressPolicy(allowed_destinations=["test.domain"]),
            resolver_func=lambda h: ["::ffff:127.0.0.1"]
        )
        success, reason, _ = broker_mapped.establish_connection("https://test.domain")
        assert success is False
        assert "returned restricted IP" in reason

        broker_link_local = EgressTransportBroker(
            policy=EgressPolicy(allowed_destinations=["test.domain"]),
            resolver_func=lambda h: ["169.254.10.1"]
        )
        success, reason, _ = broker_link_local.establish_connection("https://test.domain")
        assert success is False
        assert "returned restricted IP" in reason

        broker_invalid_ip = EgressTransportBroker(
            policy=EgressPolicy(allowed_destinations=["test.domain"]),
            resolver_func=lambda h: ["not-a-valid-ip"]
        )
        success, reason, _ = broker_invalid_ip.establish_connection("https://test.domain")
        assert success is False
        assert "returned restricted IP" in reason

    def test_socket_connect_ex_patched_branches(self):
        broker = EgressTransportBroker(
            policy=EgressPolicy(allowed_destinations=["allowed.domain"]),
            resolver_func=lambda h: ["93.184.216.34"]
        )

        with broker.enforce_socket_boundary():
            # Outside broker active context, connect_ex returns errno.EACCES
            from epistemicos.containment import _active_broker_context
            token = _active_broker_context.set(None)
            real_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                ret = real_sock.connect_ex(("allowed.domain", 443))
                assert ret == errno.EACCES
            finally:
                real_sock.close()
                _active_broker_context.reset(token)

            # 1. Non-INET socket connect_ex (Lines 1092-1094)
            mock_unix_sock = MagicMock(spec=socket.socket)
            mock_unix_sock.family = getattr(socket, "AF_UNIX", -1)
            with patch("epistemicos.containment._orig_socket_connect_ex", return_value=0) as m_ex:
                from epistemicos.containment import socket as containment_socket
                ret = containment_socket.socket.connect_ex(mock_unix_sock, "/tmp/sock")
                assert ret == 0
                m_ex.assert_called_once()

            # 2. Denied target under connect_ex returns errno.EACCES (Line 1121)
            real_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                ret = real_sock.connect_ex(("unauthorized.domain.com", 443))
                assert ret == errno.EACCES
            finally:
                real_sock.close()

            # 3. Permitted target with pinned IP under connect_ex (Line 1126)
            real_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                patch_ex = patch(
                    "epistemicos.containment._orig_socket_connect_ex", return_value=0
                )
                with patch_ex as m_ex:
                    ret = real_sock.connect_ex(("allowed.domain", 443))
                    assert ret == 0
                    expected_target = ("93.184.216.34", 443)
                    m_ex.assert_called_once_with(real_sock, expected_target)
            finally:
                real_sock.close()

    def test_http_transport_proxy_tunnel_and_ssl_context(self):
        conn_http = PinnedHTTPConnection(
            "example.com", pinned_ip="93.184.216.34", port=80
        )
        conn_http._tunnel_host = "proxy.example.com"
        with patch.object(conn_http, "_tunnel") as mock_tunnel, \
             patch.object(conn_http, "_create_connection"):
            conn_http.connect()
            mock_tunnel.assert_called_once()

        conn_https = PinnedHTTPSConnection(
            "example.com", pinned_ip="93.184.216.34", port=443
        )
        conn_https._tunnel_host = "proxy.example.com"
        conn_https._context = None
        mock_sock = MagicMock()
        mock_ssl_ctx = MagicMock()
        mock_ssl_ctx.wrap_socket.return_value = mock_sock

        with patch.object(conn_https, "_tunnel") as mock_tunnel, \
             patch.object(conn_https, "_create_connection", return_value=mock_sock), \
             patch("ssl.create_default_context", return_value=mock_ssl_ctx):
            conn_https.sock = mock_sock
            conn_https.connect()
            mock_tunnel.assert_called_once()
            mock_ssl_ctx.wrap_socket.assert_called_once_with(
                mock_sock, server_hostname="example.com"
            )

    def test_controlled_transport_network_io_error_and_max_redirects(self):
        broker = EgressTransportBroker(
            policy=EgressPolicy(
                allowed_destinations=["api.example.com", "redirect.example.com"]
            ),
            resolver_func=lambda h: ["93.184.216.34"]
        )
        transport = ControlledEgressTransport(broker=broker)

        # 1. Network I/O error (Lines 1324-1325)
        io_err = OSError("Connection reset by peer")
        with patch.object(PinnedHTTPConnection, "request", side_effect=io_err):
            with pytest.raises(socket.error, match="Egress transport network I/O error"):
                transport.request("GET", "http://api.example.com/data")

        # 2. Redirect limit exceeded (Line 1331)
        mock_resp = MagicMock()
        mock_resp.status = 302
        mock_resp.reason = "Found"
        mock_resp.getheaders.return_value = [
            ("Location", "http://redirect.example.com/loop")
        ]
        mock_resp.read.return_value = b""

        with patch.object(PinnedHTTPConnection, "request"), \
             patch.object(PinnedHTTPConnection, "getresponse", return_value=mock_resp):
            with pytest.raises(PermissionError, match="Exceeded maximum redirect limit"):
                transport.request("GET", "http://redirect.example.com/start", max_redirects=2)
