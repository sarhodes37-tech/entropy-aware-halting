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
    MAX_URL_INPUT_LEN,
)
from epistemicos.authorization import normalize_target_scope


# =========================================================================
# 1. RUNTIME SECURITY FLOOR TESTS
# =========================================================================

def test_runtime_security_floor_current_interpreter():
    """Verifies that the current test interpreter satisfies the runtime security floor (>= 3.11.4)."""
    assert sys.version_info >= (3, 11, 4), f"Interpreter {sys.version_info} is below minimum 3.11.4"
    assert epistemicos.MIN_SUPPORTED_PYTHON_VERSION == (3, 11, 4)


@pytest.mark.parametrize("rejected_version", [
    (3, 10, 12),
    (3, 11, 0),
    (3, 11, 1),
    (3, 11, 2),
    (3, 11, 3),
])
def test_runtime_security_floor_rejects_vulnerable_versions(rejected_version):
    """Verifies that importing epistemicos on Python < 3.11.4 raises an actionable RuntimeError."""
    import importlib

    class FakeVersionInfo(tuple):
        major = rejected_version[0]
        minor = rejected_version[1]
        micro = rejected_version[2]

        def __lt__(self, other):
            return (self.major, self.minor, self.micro) < other

    fake_v = FakeVersionInfo((*rejected_version, "final", 0))
    with patch("sys.version_info", fake_v):
        with pytest.raises(RuntimeError, match="Unsupported Python runtime: EpistemicOS requires Python 3\\.11\\.4\\+"):
            importlib.reload(epistemicos)

    # Restore module state
    importlib.reload(epistemicos)


@pytest.mark.parametrize("accepted_version", [
    (3, 11, 4),
    (3, 11, 5),
    (3, 12, 0),
    (3, 13, 1),
])
def test_runtime_security_floor_accepts_patched_and_newer_versions(accepted_version):
    """Verifies that 3.11.4 and newer versions pass the runtime check cleanly."""
    import importlib

    class FakeVersionInfo(tuple):
        major = accepted_version[0]
        minor = accepted_version[1]
        micro = accepted_version[2]

        def __lt__(self, other):
            return (self.major, self.minor, self.micro) < other

    fake_v = FakeVersionInfo((*accepted_version, "final", 0))
    with patch("sys.version_info", fake_v):
        mod = importlib.reload(epistemicos)
        assert mod is not None

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
    " 127.0.0.1",
    "127.0.0.1 ",
    "  127.0.0.1  ",
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
# 3. CVE-2022-45061 HARDENING: DEFENSIVE IDNA HOSTNAME RESOURCE BOUNDS
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
    "   http://example.com/api",
    "http://example.com/api   ",
    "  http://example.com/api  ",
    "\thttp://example.com/api",
    "http://example.com/api\n",
    "http://example.com\t/api",
    "http://example.com\n/api",
    "http://example.com\r/api",
    "http://example.com\x00/api",
    "http://exa\tmple.com",
    "http://exa\nmple.com",
    "http://exa\rmple.com",
    "http://example.com:80\r\n/path",
    # Percent-encoded whitespace and C0 control characters in authority
    "http://%20example.com/api",
    "http://example.com%20/api",
    "http://example%20.com/api",
    "http://%09example.com/api",
    "http://example.com%09/api",
    "http://%0Aexample.com/api",
    "http://example.com%0A/api",
    "http://%0Dexample.com/api",
    "http://example.com%0D/api",
    "http://%0Bexample.com/api",
    "http://example.com%0B/api",
    "http://%0Cexample.com/api",
    "http://example.com%0C/api",
    "http://%00example.com/api",
    "http://example.com%00/api",
    "http://exa%00mple.com/api",
])
def test_parse_url_authority_structure_rejects_embedded_whitespace_and_control_chars(malformed_url):
    """Verifies that URLs containing raw or percent-encoded whitespace/C0 control characters in authority are rejected."""
    res = parse_url_authority_structure(malformed_url)
    assert res["valid"] is False
    assert res["normalized_host"] == ""


@pytest.mark.parametrize("encoded_auth_url", [
    "http://%20example.com/api",
    "http://example.com%20/api",
    "http://%09example.com/api",
    "http://example.com%09/api",
    "http://%0Aexample.com/api",
    "http://example.com%0A/api",
    "http://%0Dexample.com/api",
    "http://example.com%0D/api",
    "http://%0Bexample.com/api",
    "http://example.com%0B/api",
    "http://%0Cexample.com/api",
    "http://example.com%0C/api",
    "http://%00example.com/api",
    "http://example.com%00/api",
])
def test_encoded_authority_whitespace_cannot_pass_egress_policy_or_guard(encoded_auth_url):
    """Verifies that percent-encoded whitespace/control characters in authority produce no normalized host and fail closed in EgressPolicy and ContainmentGuard."""
    assert normalize_destination_host(encoded_auth_url) == ""

    policy = EgressPolicy(allowed_destinations={"example.com", "*"})
    allowed, msg = policy.is_destination_allowed(encoded_auth_url)
    assert allowed is False
    assert "could not be normalized" in msg

    guard = ContainmentGuard(allowed_egress_domains=["example.com", "*"])
    receipt = guard.inspect_network_egress(encoded_auth_url)
    assert receipt.passed is False
    assert "Missing or invalid target hostname" in receipt.reason


@pytest.mark.parametrize("malformed_target", [
    " /api/users",
    "/api/users ",
    "/api/\tusers",
    "/api/\nusers",
    "/api/\rusers",
    "/api/\x00users",
    "/api/%00users",
    "/api/%0Ausers",
    "/api/%0Dusers",
    "/api/%09users",
    "http://example.com/api/\tusers",
    "http://example.com/api/\nusers",
    "http://example.com/api/%00users",
    "http://example.com/api/%0ausers",
    " http://example.com/api",
    "",
    None,
    12345,
])
def test_normalize_target_scope_raises_on_malformed_targets(malformed_target):
    """Verifies that normalize_target_scope raises ValueError for missing, empty, non-string, whitespace, control-char, and percent-encoded control anomalies."""
    with pytest.raises(ValueError):
        normalize_target_scope(malformed_target)


def test_normalize_target_scope_preserves_valid_percent_encoded_paths():
    """Verifies that legitimate percent-encoded paths (e.g., spaces, utf-8, symbols) normalize cleanly."""
    res_space = normalize_target_scope("/api/my%20documents")
    assert res_space == "target::/api/my documents"

    res_url = normalize_target_scope("https://example.com/api/%E2%9C%93/status")
    assert res_url == "target:example.com:/api/✓/status"


def test_malformed_target_fails_closed_in_authorization_and_fencing(tmp_path):
    """
    Verifies that a malformed target with whitespace or control characters:
    1. Cannot match or reuse a capability issued for root scope.
    2. Fails capability issuance and verification closed without advancing fencing generations.
    3. Cannot bypass validation via precomputed scope keys.
    4. Does not mutate storage, advance fencing tokens, or alter stored state
       (in-memory store capability state remains unmodified; persistent store
       journal file lines and content remain byte-for-byte identical).
    """
    from epistemicos.authorization import (
        canonicalize_fencing_scope,
        InMemoryAuthorizationStore,
        FileAuthorizationStore,
        CapabilityRegistry,
        AuthorizationAuthority,
        Policy,
        Capability,
    )

    policy = Policy(
        policy_id="test_policy_001",
        version="1.0.0",
        allowed_operations={"read_root", "read_file"},
        allowed_resources={"/", "/valid"},
        allowed_principals={"*"},
        allowed_executors={"*"},
    )

    # Test across both InMemoryAuthorizationStore and FileAuthorizationStore
    journal_path = str(tmp_path / "auth_journal.jsonl")
    for store in [InMemoryAuthorizationStore(), FileAuthorizationStore(store_path=journal_path)]:
        registry = CapabilityRegistry(storage_backend=store)
        authority = AuthorizationAuthority(default_policy=policy, registry=registry)

        # 1. Issue and register a legitimate capability for root scope "/"
        root_cap, reason = authority.evaluate_and_issue_capability(
            action_name="read_root",
            target="/",
            canonical_request_digest="digest_root_001",
            task_id="task_1",
        )
        assert root_cap is not None
        assert reason == "AUTHORIZATION_GRANTED"
        assert root_cap.fencing_token == 1
        root_scope = canonicalize_fencing_scope("task_1", "/")
        assert root_cap.scope_key == root_scope
        assert store.get_scope_fencing_token(root_scope) == 1

        # Capture baseline state immediately after issuing legitimate root capability
        if isinstance(store, FileAuthorizationStore):
            with open(journal_path, "r", encoding="utf-8") as jf:
                journal_lines_baseline = jf.readlines()
            assert len(journal_lines_baseline) == 1
        else:
            in_mem_caps_baseline = {
                k: v.to_dict() if hasattr(v, "to_dict") else dict(v)
                for k, v in store._capabilities.items()
            }
            assert len(in_mem_caps_baseline) == 1
            assert root_cap.token_id in in_mem_caps_baseline

        # 2. Attempt issuance using malformed targets (whitespace, control chars, percent-encoded controls, empty, non-string)
        for malformed in [
            "/\x00malformed",
            " /root",
            "/root\t",
            "/root\n",
            "/root/%00malformed",
            "/root/%0Amalformed",
            "/root/%0Dmalformed",
            "http://%20example.com/api",
            "http://example.com%20/api",
            "http://%00example.com/api",
            "",
            None,
            123,
        ]:
            try:
                bad_cap, bad_reason = authority.evaluate_and_issue_capability(
                    action_name="read_root",
                    target=malformed,
                    canonical_request_digest="digest_bad",
                    task_id="task_1",
                )
                assert bad_cap is None, f"Expected None cap for malformed target {malformed!r}"
            except ValueError:
                pass  # Raising ValueError also correctly fails closed

        # Assert that rejected operations appended no journal records or mutated in-memory capabilities
        if isinstance(store, FileAuthorizationStore):
            with open(journal_path, "r", encoding="utf-8") as jf:
                journal_lines_after_issuance = jf.readlines()
            assert len(journal_lines_after_issuance) == len(journal_lines_baseline)
            assert journal_lines_after_issuance == journal_lines_baseline
        else:
            in_mem_caps_after_issuance = {
                k: v.to_dict() if hasattr(v, "to_dict") else dict(v)
                for k, v in store._capabilities.items()
            }
            assert in_mem_caps_after_issuance == in_mem_caps_baseline

        # 3. Assert root fencing generation did not advance and root scope token is still 1
        assert store.get_scope_fencing_token(root_scope) == 1

        # 4. Attempt verification using malformed targets against root capability -> must be rejected
        for malformed in ["/\x00malformed", "/%00malformed", "/root\t", "http://%20example.com/api"]:
            ok, v_reason, cap_ret = authority.verify_capability(
                token_id=root_cap.token_id,
                action_name="read_root",
                target=malformed,
                canonical_request_digest="digest_root_001",
                executor_id="default_executor",
                task_id="task_1",
            )
            assert ok is False
            assert "TARGET_MISMATCH" in v_reason

        # Assert verification checks appended no journal records and contents match baseline
        if isinstance(store, FileAuthorizationStore):
            with open(journal_path, "r", encoding="utf-8") as jf:
                journal_lines_after_verify = jf.readlines()
            assert len(journal_lines_after_verify) == len(journal_lines_baseline)
            assert journal_lines_after_verify == journal_lines_baseline
        else:
            in_mem_caps_after_verify = {
                k: v.to_dict() if hasattr(v, "to_dict") else dict(v)
                for k, v in store._capabilities.items()
            }
            assert in_mem_caps_after_verify == in_mem_caps_baseline

        # 5. Precomputed scope key spoofing: attempting to register an external capability with spoofed root scope_key
        spoofed_cap = Capability(
            token_id="AUTH-FORGED-001",
            principal_id="agent_default",
            correlation_id="corr_1",
            request_id="req_1",
            action_name="read_root",
            target="/\x00malformed",
            canonical_request_digest="digest_spoofed",
            executor_id="default_executor",
            policy_version="1.0.0",
            created_at=100.0,
            expires_at=200.0,
            task_id="task_1",
            scope_key=root_scope,  # Spoofed root scope key for a malformed target
        )
        with pytest.raises(ValueError, match="scope_key mismatch|Malformed target"):
            registry.register_capability(spoofed_cap)

        # Confirm store still has only root_cap, fencing generation remains 1, and journal contents are identical
        assert store.get_scope_fencing_token(root_scope) == 1
        assert registry.get_capability("AUTH-FORGED-001") is None
        if isinstance(store, FileAuthorizationStore):
            with open(journal_path, "r", encoding="utf-8") as jf:
                journal_lines_final = jf.readlines()
            assert len(journal_lines_final) == len(journal_lines_baseline)
            assert journal_lines_final == journal_lines_baseline
        else:
            in_mem_caps_final = {
                k: v.to_dict() if hasattr(v, "to_dict") else dict(v)
                for k, v in store._capabilities.items()
            }
            assert in_mem_caps_final == in_mem_caps_baseline
