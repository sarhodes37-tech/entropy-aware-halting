"""
Direct Semantic Equivalence & Differential Tests for Containment Character-Class Scanning.

Validates that precompiled regular expression character scans:
  - _NETLOC_CTRL_REGEX
  - _HOST_WS_REGEX
  - _IP_INVALID_REGEX
produce bit-for-bit identical Boolean evaluation to the original generator expressions:
  - any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in unquoted_netloc)
  - any(c.isspace() for c in host_clean)
  - any(c.isspace() or c in ('+', '-', '\\x00') for c in host_str)
across:
  1. All 65,536 code points of the Basic Multilingual Plane (BMP).
  2. Unicode whitespace characters across ASCII and non-ASCII blocks.
  3. All C0 control codes (0-31) and DEL (127).
  4. Positive and negative test strings for each predicate.
"""

import unicodedata

from epistemicos.containment import (
    _NETLOC_CTRL_REGEX,
    _HOST_WS_REGEX,
    _IP_INVALID_REGEX,
    _URL_UNENCODED_CTRL_REGEX,
    _IDNA_HOSTNAME_REGEX,
    _SINGLE_INT_IP_REGEX,
)


def _orig_netloc_ctrl_check(s: str) -> bool:
    """Original generator predicate for decoded authority control-character validation."""
    return any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in s)


def _regex_netloc_ctrl_check(s: str) -> bool:
    """New compiled regex predicate for decoded authority control-character validation."""
    return bool(_NETLOC_CTRL_REGEX.search(s))


def _orig_host_ws_check(s: str) -> bool:
    """Original generator predicate for hostname whitespace validation."""
    return any(c.isspace() for c in s)


def _regex_host_ws_check(s: str) -> bool:
    """New compiled regex predicate for hostname whitespace validation."""
    return bool(_HOST_WS_REGEX.search(s))


def _orig_ip_invalid_check(s: str) -> bool:
    """Original generator predicate for numeric IP invalid character validation."""
    return any(c.isspace() or c in ("+", "-", "\x00") for c in s)


def _regex_ip_invalid_check(s: str) -> bool:
    """New compiled regex predicate for numeric IP invalid character validation."""
    return bool(_IP_INVALID_REGEX.search(s))


def _orig_url_unencoded_ctrl_check(s: str) -> bool:
    """Original generator predicate for unencoded control characters in target URLs."""
    return any(c in s for c in ('\r', '\n', '\t', '\x00', '\x0b', '\x0c'))


def _regex_url_unencoded_ctrl_check(s: str) -> bool:
    """New compiled regex predicate for unencoded control characters in target URLs."""
    return bool(_URL_UNENCODED_CTRL_REGEX.search(s))


def test_bmp_exhaustive_code_point_equivalence():
    """
    Exhaustively tests all 65,536 code points in the Basic Multilingual Plane (BMP)
    to ensure 100% equivalence between generator expressions and compiled regexes.
    """
    mismatches_netloc = []
    mismatches_host_ws = []
    mismatches_ip = []

    for code_point in range(65536):
        char = chr(code_point)

        # 1. Authority control and whitespace check
        orig_net = _orig_netloc_ctrl_check(char)
        regex_net = _regex_netloc_ctrl_check(char)
        if orig_net != regex_net:
            mismatches_netloc.append((code_point, hex(code_point), orig_net, regex_net))

        # 2. Host clean whitespace check
        orig_ws = _orig_host_ws_check(char)
        regex_ws = _regex_host_ws_check(char)
        if orig_ws != regex_ws:
            mismatches_host_ws.append((code_point, hex(code_point), orig_ws, regex_ws))

        # 3. Numeric IP invalid characters check
        orig_ip = _orig_ip_invalid_check(char)
        regex_ip = _regex_ip_invalid_check(char)
        if orig_ip != regex_ip:
            mismatches_ip.append((code_point, hex(code_point), orig_ip, regex_ip))

    assert not mismatches_netloc, f"Netloc regex mismatched on {len(mismatches_netloc)} code points: {mismatches_netloc[:5]}"
    assert not mismatches_host_ws, f"Host whitespace regex mismatched on {len(mismatches_host_ws)} code points: {mismatches_host_ws[:5]}"
    assert not mismatches_ip, f"IP invalid regex mismatched on {len(mismatches_ip)} code points: {mismatches_ip[:5]}"

    # 4. URL unencoded control characters check across all BMP code points
    mismatches_url_ctrl = []
    for code_point in range(65536):
        char = chr(code_point)
        orig_ctrl = _orig_url_unencoded_ctrl_check(char)
        regex_ctrl = _regex_url_unencoded_ctrl_check(char)
        if orig_ctrl != regex_ctrl:
            mismatches_url_ctrl.append((code_point, hex(code_point), orig_ctrl, regex_ctrl))
    assert not mismatches_url_ctrl, f"URL unencoded regex mismatched on {len(mismatches_url_ctrl)} code points"


def test_unicode_whitespace_equivalence():
    """
    Tests all Unicode whitespace characters (ASCII, separator, and non-ASCII whitespace)
    embedded in representative strings.
    """
    # Collect all Unicode whitespace code points in BMP
    unicode_spaces = [chr(cp) for cp in range(65536) if chr(cp).isspace()]
    assert len(unicode_spaces) >= 25, f"Expected at least 25 Unicode whitespace characters, found {len(unicode_spaces)}"

    for ws in unicode_spaces:
        cp = ord(ws)
        name = unicodedata.name(ws, f"UNKNOWN_U+{cp:04X}")

        # Standalone
        assert _orig_netloc_ctrl_check(ws) == _regex_netloc_ctrl_check(ws) is True, f"Failed on standalone space {name} ({hex(cp)})"
        assert _orig_host_ws_check(ws) == _regex_host_ws_check(ws) is True, f"Failed on standalone host space {name} ({hex(cp)})"
        assert _orig_ip_invalid_check(ws) == _regex_ip_invalid_check(ws) is True, f"Failed on standalone IP space {name} ({hex(cp)})"

        # Embedded in authority
        test_netloc = f"api{ws}example.com"
        assert _orig_netloc_ctrl_check(test_netloc) == _regex_netloc_ctrl_check(test_netloc) is True, f"Failed on embedded netloc space {name}"

        # Embedded in hostname
        test_host = f"cluster{ws}internal.local"
        assert _orig_host_ws_check(test_host) == _regex_host_ws_check(test_host) is True, f"Failed on embedded host space {name}"

        # Embedded in IP
        test_ip = f"192.168.{ws}1.1"
        assert _orig_ip_invalid_check(test_ip) == _regex_ip_invalid_check(test_ip) is True, f"Failed on embedded IP space {name}"


def test_c0_controls_and_del_equivalence():
    """
    Tests all C0 controls (0x00 to 0x1F) and DEL (0x7F) individually and embedded in URLs.
    """
    c0_and_del = list(range(32)) + [127]

    for cp in c0_and_del:
        ctrl_char = chr(cp)

        # Standalone
        assert _orig_netloc_ctrl_check(ctrl_char) == _regex_netloc_ctrl_check(ctrl_char) is True, f"Failed on standalone C0/DEL {hex(cp)}"

        # Embedded in authority
        netloc = f"example.com{ctrl_char}:8080"
        assert _orig_netloc_ctrl_check(netloc) == _regex_netloc_ctrl_check(netloc) is True, f"Failed on embedded C0/DEL {hex(cp)}"

        # Null byte in IP
        if cp == 0:
            ip_with_null = f"10.0.{ctrl_char}1"
            assert _orig_ip_invalid_check(ip_with_null) == _regex_ip_invalid_check(ip_with_null) is True


def test_positive_and_negative_strings_netloc_ctrl():
    """
    Validates explicit positive (rejected/flagged) and negative (allowed/clean) strings
    for the netloc control-character predicate.
    """
    # Clean strings that should NOT trigger netloc control check (False)
    clean_netlocs = [
        "example.com",
        "api.github.com:443",
        "internal-service.cluster.local:8443",
        "192.168.1.1:8080",
        "[::1]:80",
        "user:pass@service.net:5000",
        "sub-domain_name.test-hyphen.org",
        "xn--mnchen-3ya.de",
        "a" * 128 + ".com:443",
    ]

    for s in clean_netlocs:
        assert _orig_netloc_ctrl_check(s) is False
        assert _regex_netloc_ctrl_check(s) is False

    # Dirty strings that MUST trigger netloc control check (True)
    dirty_netlocs = [
        "ex ample.com",
        "api.github.com\t:443",
        "example.com\r\n",
        "service\x00.net",
        "host\x1f:80",
        "node\x7f:8080",
        " \t\r\n",
        "host\x0b.com",
        "host\x0c.com",
        "site.com\u00A0",  # Non-breaking space
        "site.com\u2003",  # Em space
        "site.com\u3000",  # Ideographic space
    ]

    for s in dirty_netlocs:
        assert _orig_netloc_ctrl_check(s) is True
        assert _regex_netloc_ctrl_check(s) is True


def test_positive_and_negative_strings_host_ws():
    """
    Validates explicit positive (rejected/flagged) and negative (allowed/clean) strings
    for the host clean whitespace predicate.
    """
    clean_hosts = [
        "example.com",
        "api-v2.service.internal",
        "127.0.0.1",
        "::1",
        "localhost",
        "a" * 63 + ".b" * 63 + ".com",
    ]

    for h in clean_hosts:
        assert _orig_host_ws_check(h) is False
        assert _regex_host_ws_check(h) is False

    dirty_hosts = [
        "ex ample.com",
        "example .com",
        " example.com",
        "example.com ",
        "example\t.com",
        "example\n.com",
        "example\u2002.com",  # En space
        "example\u2009.com",  # Thin space
        "example\u202F.com",  # Narrow no-break space
    ]

    for h in dirty_hosts:
        assert _orig_host_ws_check(h) is True
        assert _regex_host_ws_check(h) is True


def test_positive_and_negative_strings_ip_invalid():
    """
    Validates explicit positive (rejected/flagged) and negative (allowed/clean) strings
    for the numeric IP validation predicate.
    """
    clean_ip_strings = [
        "127.0.0.1",
        "0177.0.0.1",
        "0x7f000001",
        "2130706433",
        "10.0.0.1",
        "192.168.1.1",
        "0.0.0.0",
        "255.255.255.255",
        "0377.0377.0377.0377",
        "0xff.0xff.0xff.0xff",
        "0",
        "1",
    ]

    for ip in clean_ip_strings:
        assert _orig_ip_invalid_check(ip) is False
        assert _regex_ip_invalid_check(ip) is False

    dirty_ip_strings = [
        "+127.0.0.1",
        "-127.0.0.1",
        "127.0.0.1+",
        "127.0.0.1-",
        " 127.0.0.1",
        "127.0.0.1 ",
        "127. 0.0.1",
        "127.0.0.1\x00",
        "\x00127.0.0.1",
        "127\t.0.0.1",
        "127\n.0.0.1",
        "127.0.0.1\u00A0",
        "0x7f+0001",
    ]

    for ip in dirty_ip_strings:
        assert _orig_ip_invalid_check(ip) is True
        assert _regex_ip_invalid_check(ip) is True
