"""
Unit tests and equivalence verification for normalize_target_scope optimization.

Verifies:
1. Decision and functional equivalence between direct implementation and cached API.
2. Exception equivalence across malformed inputs, control characters, and length bounds.
3. Bounded cache behavior (hits, misses, and bypass for inputs > 512 characters).
4. Fencing scope integration via canonicalize_fencing_scope.
"""

import pytest
from epistemicos.authorization import (
    MAX_TARGET_INPUT_LEN,
    canonicalize_fencing_scope,
    normalize_target_scope,
    _cached_normalize_target_scope,
    _normalize_target_scope_impl,
)


@pytest.fixture(autouse=True)
def clear_target_scope_cache():
    """Ensure clean cache state between test executions."""
    _cached_normalize_target_scope.cache_clear()
    yield
    _cached_normalize_target_scope.cache_clear()


VALID_SAMPLE_TARGETS = [
    "/",
    "/api",
    "/api/v1/users",
    "/users/123/profile",
    "/users/../users/admin",
    "/a/b/../../c",
    "files/data/report.json",
    "/files/data/report.json",
    "/api?param=1&filter=true",
    "/api#anchor",
    "http://example.com",
    "http://example.com/",
    "http://example.com:8080/api/v1",
    "https://secure.internal.net/gateway",
    "https://api.example.com/v2/items?filter=active#results",
    "/api/my%20documents",
    "https://example.com/api/%E2%9C%93/status",
    "/foo\\bar/baz",
    # Exactly 512 characters
    "/api/" + ("sub/" * 126) + "res",
    # Boundary length within cache limit
    "/" + ("a" * 510),
]

MALFORMED_TARGETS = [
    None,
    12345,
    True,
    False,
    "",
    "   ",
    "http://example.com/a b",
    "http://example.com/a\nb",
    "http://exa%20mple.com/path",
    "http://example.com/api%00bad",
    "http://example.com/api%0Abad",
    "http://example.com/api%0Dbad",
    "http://example.com/api%09bad",
    "/path/\x00/bad",
    "/path/\x0b/bad",
    "/path/\x0c/bad",
    "http://example.com:8080/path\x00bad",
    "http://example.com:8080/path\r\nbad",
    "http://example.com:8080/path\tbad",
    "http://[bad netloc with spaces]/path",
    "a" * (MAX_TARGET_INPUT_LEN + 1),
]


def test_functional_equivalence_with_uncached_impl():
    """Verifies that normalize_target_scope returns identical output to direct implementation."""
    for target in VALID_SAMPLE_TARGETS:
        expected = _normalize_target_scope_impl(target)
        actual = normalize_target_scope(target)
        assert actual == expected, f"Equivalence failure for target: {target!r}"


def test_exception_equivalence_on_malformed_targets():
    """Verifies that invalid targets fail closed with ValueError identically."""
    for malformed in MALFORMED_TARGETS:
        if isinstance(malformed, str):
            with pytest.raises(ValueError):
                _normalize_target_scope_impl(malformed)

        with pytest.raises(ValueError):
            normalize_target_scope(malformed)


def test_cache_hit_and_miss_behavior():
    """Verifies that repeated requests hit cache and increment cache statistics."""
    initial_info = _cached_normalize_target_scope.cache_info()
    assert initial_info.currsize == 0

    target = "/db/accounts/balance"

    # First call -> cache miss
    res1 = normalize_target_scope(target)
    info_after_first = _cached_normalize_target_scope.cache_info()
    assert info_after_first.misses == initial_info.misses + 1
    assert info_after_first.hits == initial_info.hits
    assert info_after_first.currsize == 1

    # Second call -> cache hit
    res2 = normalize_target_scope(target)
    info_after_second = _cached_normalize_target_scope.cache_info()
    assert info_after_second.hits == initial_info.hits + 1
    assert info_after_second.currsize == 1
    assert res1 == res2


def test_cache_bypass_for_large_targets():
    """Verifies targets longer than 512 characters bypass the cache without polluting it."""
    # Construct a valid long target > 512 chars but <= MAX_TARGET_INPUT_LEN
    long_target = "/" + ("x" * 600)
    assert len(long_target) > 512
    assert len(long_target) <= MAX_TARGET_INPUT_LEN

    initial_info = _cached_normalize_target_scope.cache_info()

    res1 = normalize_target_scope(long_target)
    assert res1 == f"target::{long_target}"

    info_after_call = _cached_normalize_target_scope.cache_info()
    # Cache was bypassed: misses, hits, and currsize should be unchanged
    assert info_after_call.currsize == initial_info.currsize
    assert info_after_call.hits == initial_info.hits
    assert info_after_call.misses == initial_info.misses


def test_canonicalize_fencing_scope_integration():
    """Verifies canonicalize_fencing_scope seamlessly integrates with cached normalization."""
    scope1 = canonicalize_fencing_scope("task-42", "/db/users")
    scope2 = canonicalize_fencing_scope("task-42", "/db/users")
    assert scope1 == scope2
    assert scope1 == "task:task-42|target::/db/users"

    # Global task fallback
    global_scope = canonicalize_fencing_scope(None, "https://api.external.com/v1")
    assert global_scope == "task:__GLOBAL__|target:api.external.com:/v1"


def test_exhaustive_unicode_and_control_character_equivalence():
    """
    Exhaustively verifies semantic equivalence between generator and regex character validation
    across all ASCII and Unicode code points up to 0xFFFF, including:
    - All 32 C0 control characters (0x00..0x1F) and DEL (0x7F)
    - Unicode whitespace characters (e.g. U+00A0, U+1680, U+2000..U+200A, U+2028, U+2029, U+202F, U+205F, U+3000)
    - Percent-encoded (%XX) and literal raw inputs in authority and path components.
    """
    from epistemicos.authorization import (
        _TARGET_UNENCODED_CTRL_REGEX,
        _TARGET_AUTHORITY_CTRL_REGEX,
        _TARGET_DECODED_CTRL_REGEX,
    )

    # 1. Direct predicate equivalence across entire BMP code space (0..65535)
    for cp in range(0x10000):
        ch = chr(cp)

        # Unencoded predicate
        gen_unenc = any(c.isspace() or c in ("\x00", "\x0b", "\x0c") for c in ch)
        reg_unenc = bool(_TARGET_UNENCODED_CTRL_REGEX.search(ch))
        assert gen_unenc == reg_unenc, f"Unencoded predicate divergence at U+{cp:04X}"

        # Decoded authority predicate
        gen_auth = any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in ch)
        reg_auth = bool(_TARGET_AUTHORITY_CTRL_REGEX.search(ch))
        assert gen_auth == reg_auth, f"Authority predicate divergence at U+{cp:04X}"

        # Decoded path predicate
        gen_dec = any(c in ch for c in ("\x00", "\r", "\n", "\t", "\x0b", "\x0c"))
        reg_dec = bool(_TARGET_DECODED_CTRL_REGEX.search(ch))
        assert gen_dec == reg_dec, f"Decoded path predicate divergence at U+{cp:04X}"

    # 2. End-to-end normalization acceptance / rejection equivalence
    # Explicit Unicode whitespace samples
    unicode_spaces = [
        "\u00A0",  # NO-BREAK SPACE
        "\u1680",  # OGHAM SPACE MARK
        "\u2000",  # EN QUAD
        "\u2002",  # EN SPACE
        "\u2007",  # FIGURE SPACE
        "\u2009",  # THIN SPACE
        "\u2028",  # LINE SEPARATOR
        "\u2029",  # PARAGRAPH SEPARATOR
        "\u202F",  # NARROW NO-BREAK SPACE
        "\u205F",  # MEDIUM MATHEMATICAL SPACE
        "\u3000",  # IDEOGRAPHIC SPACE
    ]
    for ws in unicode_spaces:
        # Unencoded Unicode whitespace in raw target must be rejected
        with pytest.raises(ValueError):
            normalize_target_scope(f"/path/{ws}/endpoint")

    # 3. Percent-encoded variants in authority and path
    # Authority rejection: %00..%1F, %7F, and %20 in authority
    for cp in list(range(32)) + [127, 32]:
        encoded_auth = f"http://service%{cp:02x}.corp/v1"
        with pytest.raises(ValueError):
            normalize_target_scope(encoded_auth)

    # Path rejection: decoded NUL and control characters (%00, %0a, %0d, %09, %0b, %0c)
    for bad_hex in ("00", "0a", "0d", "09", "0b", "0c", "0A", "0D", "0B", "0C"):
        encoded_path = f"/api/v1/resource%{bad_hex}sub"
        with pytest.raises(ValueError):
            normalize_target_scope(encoded_path)

    # Path acceptance: non-prohibited percent-encoded characters (e.g. %20 space, %2F slash, %2D hyphen)
    # in path should be decoded and normalized properly
    res_space = normalize_target_scope("/api/my%20documents")
    assert res_space == "target::/api/my documents"

    res_hyphen = normalize_target_scope("/api/item%2D123")
    assert res_hyphen == "target::/api/item-123"
