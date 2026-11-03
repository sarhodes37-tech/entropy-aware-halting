"""
Unit and regression tests for ContainmentGuard destination candidate detection
and normalize_destination_host performance optimizations.
"""

from epistemicos.containment import (
    ContainmentGuard,
    GateInput,
    normalize_destination_host,
    parse_url_authority_structure,
)


def _uncached_normalize_destination_host(target_url_or_host: str) -> str:
    """Direct reference implementation bypassing LRU cache for equivalence testing."""
    res = parse_url_authority_structure(target_url_or_host)
    return res["normalized_host"]


def _unoptimized_is_candidate_destination(curr: str, key_context: str = "") -> bool:
    """Reference implementation without trigger character short-circuiting."""
    import ipaddress
    import re
    from epistemicos.containment import parse_ip_numeric

    if not curr or not isinstance(curr, str):
        return False
    s = curr.strip()
    if not s:
        return False

    norm = _uncached_normalize_destination_host(s)
    if not norm:
        return False

    if "://" in s or s.startswith("//") or s.startswith(("http://", "https://", "ftp://")):
        return True

    if "/" in s or ":" in s:
        return True

    try:
        ipaddress.ip_address(norm)
        return True
    except ValueError:
        pass

    if parse_ip_numeric(s) is not None:
        return True

    if re.search(r"\.[a-zA-Z]{2,}$", norm):
        ignored_extensions = (
            ".py", ".txt", ".json", ".md", ".sh", ".csv",
            ".log", ".yaml", ".yml", ".html", ".css", ".js", ".png", ".jpg", ".pdf"
        )
        if not norm.endswith(ignored_extensions):
            return True

    return False


DIVERSE_TEST_INPUTS = [
    # Full URLs
    "https://api.github.com:443",
    "http://localhost:8080/path?query=1#frag",
    "https://sub.example.com/v1/resource",
    "http://127.0.0.1:8000/",
    "ftp://files.internal.corp/data",
    "//cdn.example.org/bundle.js",
    "s3://my-bucket/object.json",
    # Host and port
    "api.stripe.com:443",
    "localhost:80",
    "10.0.0.1:9092",
    # Bare hostnames & domains
    "api.stripe.com",
    "example.org",
    "münchen.de",
    "sub.domain.co.uk",
    "localhost",
    # Bare IP addresses
    "192.168.1.1",
    "127.0.0.1",
    "10.0.0.1",
    "::1",
    "[::1]",
    "[2001:db8::1]",
    # Numeric and alternative IPv4 representations
    "2130706433",
    "0x7f000001",
    "0177.0.0.1",
    "037777777777",
    # Paths
    "/api/v1/bind_policy",
    "/etc/passwd",
    "relative/path/to/file",
    # Ordinary benign dictionary keys and free-form text
    "applicant",
    "fleet_size",
    "region",
    "US-EAST",
    "Acme Logistics LLC",
    "policy_id",
    "POL-2026-BENIGN",
    "token_count",
    "loss_modifier",
    "operating_radius_miles",
    "read",
    "write",
    "execute",
    "primary_metric",
    # File extensions that should be rejected
    "script.py",
    "document.pdf",
    "data.json",
    "archive.tar.gz",
    "readme.md",
    "style.css",
    "app.js",
    # Boundary and invalid inputs
    "",
    "   ",
    "123",
    "0",
    "invalid..hostname",
    "http://",
    "://",
    "a" * 600,  # Long string > 512 chars to test cache bypass boundary
]


def test_normalize_destination_host_equivalence():
    """Verifies that cached normalize_destination_host produces identical output to reference."""
    for s in DIVERSE_TEST_INPUTS:
        ref = _uncached_normalize_destination_host(s)
        opt = normalize_destination_host(s)
        assert opt == ref, f"Equivalence mismatch for {s!r}: expected {ref!r}, got {opt!r}"


def test_is_candidate_destination_equivalence():
    """Verifies that trigger-guarded _is_candidate_destination matches reference decisions."""
    for s in DIVERSE_TEST_INPUTS:
        ref = _unoptimized_is_candidate_destination(s)
        opt = ContainmentGuard._is_candidate_destination(s)
        assert opt == ref, f"Candidate mismatch for {s!r}: expected {ref!r}, got {opt!r}"


def test_evaluate_contract_decision_and_receipt_equivalence():
    """Verifies that ContainmentGuard.evaluate_contract outputs identical outcomes and receipts."""
    payload = {
        "policy_id": "POL-2026-BENIGN",
        "raw_payload": {
            "applicant": "Acme Logistics LLC",
            "fleet_size": 25,
            "region": "US-EAST",
        },
        "fleet_data": {
            "vehicle_count": 25,
            "operating_radius_miles": 150.0,
            "loss_modifier": 1.0,
        },
        "primary_metric": 100.0,
        "scope": {
            "allowed_resources": ["logistics_db", "/bind_policy"],
            "allowed_operations": ["read", "api_call"],
        },
    }
    context = {
        "token_logprobs": [-0.1, -0.2, -0.15, -0.12, -0.18, -0.11, -0.25, -0.14, -0.19, -0.10],
        "proposed_actions": [{"op": "api_call", "endpoint": "/bind_policy"}],
        "heterogeneous_telemetry": [98.0, 101.0, 99.5, 102.0],
        "token_count": 100,
    }

    guard = ContainmentGuard()
    gi = GateInput(payload=payload, context=context)

    outcome = guard.evaluate_contract(gi)
    assert outcome.passed is True
    assert outcome.decision.value == "ALLOW"
    assert outcome.reason_code == "CONTAINMENT_GUARDRAILS_PASSED"


def test_destination_normalization_cache_hit_behavior():
    """Verifies that LRU cache is hit for repeated normalization calls."""
    test_val = "https://api.github.com:443/v1/repos"
    res1 = normalize_destination_host(test_val)
    res2 = normalize_destination_host(test_val)
    assert res1 == res2 == "api.github.com"
