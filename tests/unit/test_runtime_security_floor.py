"""
Regression test suite for Python Runtime Security Floor & Standard-Library Hardening.

Covers:
1. Runtime Security Floor Enforcement (Python >= 3.11 requirement).
2. CVE-2020-10735 Hardening: Bounded numeric IP parsing in parse_ip_numeric().
   - Standard IPv4 dotted forms.
   - Intentionally supported legacy forms (hex, octal, dotted octal, dword).
   - Maximum length bounds and immediate over-limit cases.
   - Pathological / DoS long inputs (decimal, hex, octal).
   - Ordering verification (bounds checked before integer conversion / socket.inet_aton).
   - Control characters, signs, and ambiguous whitespace rejection.
3. CVE-2022-45061 Hardening: Bounded IDNA hostname processing in parse_url_authority_structure().
   - Valid ASCII and IDN hostnames.
   - RFC 1035 / RFC 5890 boundary lengths (253 char hostname, 63 char label).
   - Oversized hostnames and labels rejected before IDNA.
   - Pathological Unicode length inputs rejected.
   - Rejection fails closed with valid=False and empty normalized_host.
4. CVE-2023-24329 Hardening: URL whitespace and control-character handling.
   - Leading/trailing whitespace vs embedded whitespace/tabs/newlines.
   - Control character injection in URL authority and target scope.
   - Consistent canonicalization between authorization and egress.
"""

import sys
import unittest.mock
from unittest.mock import patch
import ipaddress
import pytest

import epistemicos
from epistemicos.containment import (
    parse_ip_numeric,
    parse_url_authority_structure,
    normalize_destination_host,
    EgressPolicy,
    ContainmentGuard,
    MAX_IPV4_NUMERIC_STR_LEN,
    MAX_IPV4_PART_STR_LEN,
    MAX_URL_INPUT_LEN,
    MAX_DNS_HOSTNAME_LEN,
    MAX_DNS_LABEL_LEN,
)
from epistemicos.authorization import normalize_target_scope


# =========================================================================
# 1. RUNTIME SECURITY FLOOR TESTS
# =========================================================================

def test_runtime_security_floor_current_interpreter():
    """Verifies that the current test interpreter satisfies the runtime security floor (>= 3.11)."""
    assert sys.version_info >= (3, 11), f"Interpreter {sys.version_info} is below minimum 3.11"
    assert epistemicos.MIN_SUPPORTED_PYTHON_VERSION == (3, 11)


def test_runtime_security_floor_rejects_python_310():
    """Verifies that importing epistemicos on Python < 3.11 raises an actionable RuntimeError."""
    import importlib

    class FakeVersionInfo(tuple):
        major = 3
        minor = 10
        micro = 12

        def __lt__(self, other):
            return (self.major, self.minor) < other

    fake_v = FakeVersionInfo((3, 10, 12, "final", 0))
    with patch("sys.version_info", fake_v):
        with pytest.raises(RuntimeError, match="Unsupported Python runtime: EpistemicOS requires Python 3.11\\+"):
            importlib.reload(epistemicos)

    # Restore module state
    importlib.reload(epistemicos)


# =========================================================================
# 2. CVE-2020-10735 HARDENING: BOUNDED NUMERIC IP PARSING
# =========================================================================

@pytest.mark.parametrize("valid_ip,expected", [
    ("127.0.0.1", ipaddress.IPv4Address("127.0.0.1")),
    ("10.0.0.1.", ipaddress.IPv4Address("10.0.0.1")),
    ("192.168.1.1", ipaddress.IPv4Address("192.168.1.1")),
    ("0.0.0.0", ipaddress.IPv4Address("0.0.0.0")),
    ("255.255.255.255", ipaddress.IPv4Address("255.255.255.255")),
    ("2130706433", ipaddress.IPv4Address("127.0.0.1")),
    ("4294967295", ipaddress.IPv4Address("255.255.255.255")),
    ("0x7f000001", ipaddress.IPv4Address("127.0.0.1")),
    ("0X7F000001", ipaddress.IPv4Address("127.0.0.1")),
    ("0xffffffff", ipaddress.IPv4Address("255.255.255.255")),
    ("017700000001", ipaddress.IPv4Address("127.0.0.1")),
    ("0177.0.0.1", ipaddress.IPv4Address("127.0.0.1")),
    ("0x7f.0.0.1", ipaddress.IPv4Address("127.0.0.1")),
    ("127.0x0.0x0.1", ipaddress.IPv4Address("127.0.0.1")),
])
def test_parse_ip_numeric_legitimate_forms(valid_ip, expected):
    """Verifies that all intentionally supported legitimate IPv4 forms parse correctly."""
    assert parse_ip_numeric(valid_ip) == expected


def test_parse_ip_numeric_boundary_lengths():
    """Verifies strict length enforcement on boundary and immediately-over-limit inputs."""
    valid_hex = "0x000000007f000001"
    assert parse_ip_numeric(valid_hex) == ipaddress.IPv4Address("127.0.0.1")

    exact_31 = "0x" + "0" * 21 + "7f000001"
    assert len(exact_31) == 31
    assert parse_ip_numeric(exact_31) == ipaddress.IPv4Address("127.0.0.1")

    exact_32 = "0x" + "0" * 22 + "7f000001"
    assert len(exact_32) == 32
    assert parse_ip_numeric(exact_32) == ipaddress.IPv4Address("127.0.0.1")

    over_32 = "0x" + "0" * 23 + "7f000001"
    assert len(over_32) == 33
    assert parse_ip_numeric(over_32) is None


@pytest.mark.parametrize("pathological_input", [
    "1" * 100,
    "9" * 4301,  # Exceeds Python default sys.get_int_max_str_digits (4300)
    "0x" + "f" * 100,
    "0" + "7" * 100,
    "0" * 100 + "127.0.0.1",
    "127." + "0" * 100 + ".0.1",
])
def test_parse_ip_numeric_pathological_dos_strings(pathological_input):
    """Verifies that pathological long inputs are rejected immediately without triggering expensive conversions."""
    assert parse_ip_numeric(pathological_input) is None


def test_parse_ip_numeric_bounds_execute_before_conversion():
    """Uses mocks to verify that length bounds check executes before socket.inet_aton or int conversion."""
    oversized = "1" * (MAX_IPV4_NUMERIC_STR_LEN + 1)
    with patch("socket.inet_aton") as mock_inet_aton, patch("re.match") as mock_match:
        res = parse_ip_numeric(oversized)
        assert res is None
        mock_inet_aton.assert_not_called()
        mock_match.assert_not_called()


@pytest.mark.parametrize("invalid_chars", [
    "+127.0.0.1",
    "-127.0.0.1",
    "127.0.0.1\x00",
    "127.0.0.1\t",
    "127.0.0.1\n",
    "127. 0.0.1",
    "0x7f000001+1",
])
def test_parse_ip_numeric_rejects_signs_and_control_chars(invalid_chars):
    """Verifies parse_ip_numeric rejects signs, control chars, spaces, and embedded nulls deterministically."""
    assert parse_ip_numeric(invalid_chars) is None


# =========================================================================
# 3. CVE-2022-45061 HARDENING: BOUNDED IDNA HOSTNAME PROCESSING
# =========================================================================

def test_parse_url_authority_structure_valid_ascii_and_idna():
    """Verifies legitimate ASCII and IDN domain names parse correctly."""
    ascii_res = parse_url_authority_structure("https://api.github.com/v1")
    assert ascii_res["valid"] is True
    assert ascii_res["normalized_host"] == "api.github.com"
    assert ascii_res["port"] == 443

    idna_res = parse_url_authority_structure("https://münchen.de/portal")
    assert idna_res["valid"] is True
    assert idna_res["normalized_host"] == "xn--mnchen-3ya.de"
    assert idna_res["port"] == 443


def test_parse_url_authority_structure_dns_boundaries():
    """Verifies maximum valid hostname (253 chars) and label (63 chars) boundaries."""
    label63 = "a" * 63
    label61 = "b" * 61
    host253 = f"{label63}.{label63}.{label63}.{label61}"
    assert len(host253) == 253
    res253 = parse_url_authority_structure(f"https://{host253}/path")
    assert res253["valid"] is True
    assert res253["normalized_host"] == host253

    # Exceeding 253 chars -> 254 chars must be rejected
    host254 = f"{label63}.{label63}.{label63}.{'b'*62}"
    assert len(host254) == 254
    res254 = parse_url_authority_structure(f"https://{host254}/path")
    assert res254["valid"] is False
    assert res254["normalized_host"] == ""

    # Label exceeding 63 chars (64 chars) must be rejected
    label64 = "a" * 64
    res_label64 = parse_url_authority_structure(f"https://{label64}.example.com/path")
    assert res_label64["valid"] is False
    assert res_label64["normalized_host"] == ""


def test_parse_url_authority_structure_pathological_unicode():
    """Verifies that pathological or oversized Unicode inputs fail closed without quadratic DoS."""
    unicode_long_label = "ö" * 64
    res = parse_url_authority_structure(f"https://{unicode_long_label}.com")
    assert res["valid"] is False
    assert res["normalized_host"] == ""

    oversized_url = "https://example.com/" + ("x" * 5000)
    assert len(oversized_url) > MAX_URL_INPUT_LEN
    res_url = parse_url_authority_structure(oversized_url)
    assert res_url["valid"] is False
    assert res_url["normalized_host"] == ""


def test_rejected_idna_hostname_cannot_pass_egress_policy_or_guard():
    """Verifies that rejected oversized hostnames fail closed and cannot pass EgressPolicy or ContainmentGuard."""
    oversized_host = "a" * 254 + ".com"
    policy = EgressPolicy(allowed_destinations={"*"})
    allowed, msg = policy.is_destination_allowed(oversized_host)
    assert allowed is False
    assert "could not be normalized" in msg

    guard = ContainmentGuard(allowed_egress_domains=["*"])
    receipt = guard.inspect_network_egress(f"https://{oversized_host}/api")
    assert receipt.passed is False
    assert "Missing or invalid target hostname" in receipt.reason


# =========================================================================
# 4. CVE-2023-24329 HARDENING: URL WHITESPACE & CONTROL CHARACTERS
# =========================================================================

@pytest.mark.parametrize("malformed_url", [
    "http://example.com\t/api",
    "http://example.com\n/api",
    "http://example.com\r/api",
    "http://example.com\x00/api",
    "http://exa\tmple.com",
    "http://exa\nmple.com",
    "http://exa\rmple.com",
    "http://example.com:80\r\n/path",
])
def test_parse_url_authority_structure_rejects_embedded_whitespace_and_control_chars(malformed_url):
    """Verifies that URLs containing unencoded control characters, tabs, or newlines are rejected."""
    res = parse_url_authority_structure(malformed_url)
    assert res["valid"] is False
    assert res["normalized_host"] == ""


@pytest.mark.parametrize("malformed_target", [
    "/api/\tusers",
    "/api/\nusers",
    "/api/\rusers",
    "/api/\x00users",
    "http://example.com/api/\tusers",
    "http://example.com/api/\nusers",
])
def test_normalize_target_scope_rejects_control_characters(malformed_target):
    """Verifies that normalize_target_scope rejects unencoded control characters and returns safe fallback."""
    res = normalize_target_scope(malformed_target)
    assert res == "target:/:/"


def test_leading_trailing_whitespace_normalization_consistency():
    """
    Verifies that leading/trailing whitespace on URLs is cleanly normalized once
    and both authorization and network egress resolve to the exact same canonical host.
    """
    raw_url = "   https://api.github.com/v1/repos   "
    canonical_host = normalize_destination_host(raw_url)
    assert canonical_host == "api.github.com"

    auth_res = parse_url_authority_structure(raw_url)
    assert auth_res["valid"] is True
    assert auth_res["normalized_host"] == "api.github.com"
    assert auth_res["port"] == 443

    assert auth_res["normalized_host"] == canonical_host
