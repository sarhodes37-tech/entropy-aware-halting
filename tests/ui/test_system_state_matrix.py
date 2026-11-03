"""
Deterministic unit test suite for Observatory input normalization and system state derivation matrix.

Verifies:
1. normalizeMetricValue handles numbers, numeric strings, null, undefined, booleans, negative numbers, floats, objects.
2. deriveSystemState enforces operational precedence rules and reasons:
   - Both integrity sources verified, no operational exceptions -> READY
   - Audit unavailable, provenance verified -> UNVERIFIED (single unavailable source prevents READY)
   - Provenance unavailable, audit verified -> UNVERIFIED (single unavailable source prevents READY)
   - Both unavailable -> UNVERIFIED
   - Either source unverified -> UNVERIFIED
   - Audit corrupted -> BLOCKED
   - Provenance corrupted -> BLOCKED
   - Operational failures with verified integrity -> BLOCKED
   - Policy halts with verified integrity -> HALTED
   - Authorization denials with verified integrity -> DEGRADED
   - Parse errors with verified integrity -> DEGRADED
   - Missing and malformed metric values -> handled gracefully without false READY
   - Conflicting conditions (e.g. corruption trumps halts, halts trump unverified operational denials).
"""

import json
import pytest
from pathlib import Path
from epistemicos.ui.server import create_server
from epistemicos.ui.adapters import ObservatoryDataAdapter

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


@pytest.fixture
def dummy_server(tmp_path):
    server = create_server(host="127.0.0.1", port=0)
    import threading
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


@pytest.mark.skipif(not PLAYWRIGHT_AVAILABLE, reason="playwright not installed")
def test_normalize_metric_value(dummy_server):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(f"{dummy_server}/index.html")

        # Test normalizeMetricValue
        cases = [
            (0, {"status": "VALID", "value": 0}),
            (42, {"status": "VALID", "value": 42}),
            ("100", {"status": "VALID", "value": 100}),
            ("  55  ", {"status": "VALID", "value": 55}),
            (None, {"status": "UNAVAILABLE", "value": None}),
            (True, {"status": "INVALID", "value": None}),
            (False, {"status": "INVALID", "value": None}),
            (-1, {"status": "INVALID", "value": None}),
            ("-5", {"status": "INVALID", "value": None}),
            (3.14, {"status": "INVALID", "value": None}),
            ("abc", {"status": "INVALID", "value": None}),
            ("", {"status": "INVALID", "value": None}),
            ("   ", {"status": "INVALID", "value": None}),
            ({"val": 1}, {"status": "INVALID", "value": None}),
            ([1, 2], {"status": "INVALID", "value": None}),
        ]

        for inp, expected in cases:
            res = page.evaluate("(val) => window.ObservatoryApp.normalizeMetricValue(val)", inp)
            assert res == expected, f"Failed for input {inp}: expected {expected}, got {res}"

        browser.close()


@pytest.mark.skipif(not PLAYWRIGHT_AVAILABLE, reason="playwright not installed")
def test_derive_system_state_matrix(dummy_server):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(f"{dummy_server}/index.html")

        # 1. Healthy baseline: both verified, 0 exceptions -> READY
        d_ready = {
            "status_flags": {"audit_data_available": True, "provenance_data_available": True},
            "audit_integrity": {"status": "VERIFIED"},
            "provenance_integrity": {"status": "VERIFIED"},
            "metrics": {"total_executions": 10, "authorization_denials": 0, "halts": 0, "execution_failures": 0, "parse_error_count": 0}
        }
        res_ready = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_ready)
        assert res_ready["state"] == "READY"
        assert "zero active operational exceptions" in res_ready["reason"]

        # 2. Audit unavailable, provenance verified -> UNVERIFIED (single unavailable source prevents READY)
        d_audit_unavail = {
            "status_flags": {"audit_data_available": False, "provenance_data_available": True},
            "audit_integrity": {"status": "UNAVAILABLE"},
            "provenance_integrity": {"status": "VERIFIED"},
            "metrics": {"total_executions": 10, "authorization_denials": 0, "halts": 0, "execution_failures": 0, "parse_error_count": 0}
        }
        res_audit_unavail = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_audit_unavail)
        assert res_audit_unavail["state"] == "UNVERIFIED"
        assert "Audit Trail unavailable" in res_audit_unavail["reason"]

        # 3. Provenance unavailable, audit verified -> UNVERIFIED
        d_prov_unavail = {
            "status_flags": {"audit_data_available": True, "provenance_data_available": False},
            "audit_integrity": {"status": "VERIFIED"},
            "provenance_integrity": {"status": "UNAVAILABLE"},
            "metrics": {"total_executions": None, "authorization_denials": None, "halts": 0, "execution_failures": None, "parse_error_count": 0}
        }
        res_prov_unavail = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_prov_unavail)
        assert res_prov_unavail["state"] == "UNVERIFIED"
        assert "Provenance Store unavailable" in res_prov_unavail["reason"]

        # 4. Both unavailable -> UNVERIFIED
        d_both_unavail = {
            "status_flags": {"audit_data_available": False, "provenance_data_available": False},
            "audit_integrity": {"status": "UNAVAILABLE"},
            "provenance_integrity": {"status": "UNAVAILABLE"},
            "metrics": {"total_executions": None, "authorization_denials": None, "halts": None, "execution_failures": None, "parse_error_count": 0}
        }
        res_both_unavail = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_both_unavail)
        assert res_both_unavail["state"] == "UNVERIFIED"
        assert "Audit Trail unavailable" in res_both_unavail["reason"]
        assert "Provenance Store unavailable" in res_both_unavail["reason"]

        # 5. Either unverified (e.g. audit UNVERIFIED) -> UNVERIFIED
        d_unverified = {
            "status_flags": {"audit_data_available": True, "provenance_data_available": True},
            "audit_integrity": {"status": "UNVERIFIED"},
            "provenance_integrity": {"status": "VERIFIED"},
            "metrics": {"total_executions": 5, "authorization_denials": 0, "halts": 0, "execution_failures": 0, "parse_error_count": 0}
        }
        res_unverified = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_unverified)
        assert res_unverified["state"] == "UNVERIFIED"
        assert "Audit Trail unverified" in res_unverified["reason"]

        # 6. Audit corrupted -> BLOCKED
        d_audit_corrupt = {
            "status_flags": {"audit_data_available": True, "provenance_data_available": True},
            "audit_integrity": {"status": "CORRUPTED"},
            "provenance_integrity": {"status": "VERIFIED"},
            "metrics": {"total_executions": 5, "authorization_denials": 0, "halts": 0, "execution_failures": 0, "parse_error_count": 0}
        }
        res_audit_corrupt = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_audit_corrupt)
        assert res_audit_corrupt["state"] == "BLOCKED"
        assert "Cryptographic integrity failure positively detected in Audit Trail" in res_audit_corrupt["reason"]

        # 7. Provenance corrupted -> BLOCKED
        d_prov_corrupt = {
            "status_flags": {"audit_data_available": True, "provenance_data_available": True},
            "audit_integrity": {"status": "VERIFIED"},
            "provenance_integrity": {"status": "CORRUPTED"},
            "metrics": {"total_executions": 5, "authorization_denials": 0, "halts": 0, "execution_failures": 0, "parse_error_count": 0}
        }
        res_prov_corrupt = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_prov_corrupt)
        assert res_prov_corrupt["state"] == "BLOCKED"
        assert "Cryptographic integrity failure positively detected in Provenance Store" in res_prov_corrupt["reason"]

        # 8. Operational failure with verified integrity -> BLOCKED
        d_failures = {
            "status_flags": {"audit_data_available": True, "provenance_data_available": True},
            "audit_integrity": {"status": "VERIFIED"},
            "provenance_integrity": {"status": "VERIFIED"},
            "metrics": {"total_executions": 5, "authorization_denials": 0, "halts": 0, "execution_failures": 2, "parse_error_count": 0}
        }
        res_failures = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_failures)
        assert res_failures["state"] == "BLOCKED"
        assert "Runtime execution failure(s) detected (2 failure(s))" in res_failures["reason"]

        # 9. Policy halts with verified integrity -> HALTED
        d_halts = {
            "status_flags": {"audit_data_available": True, "provenance_data_available": True},
            "audit_integrity": {"status": "VERIFIED"},
            "provenance_integrity": {"status": "VERIFIED"},
            "metrics": {"total_executions": 5, "authorization_denials": 0, "halts": 1, "execution_failures": 0, "parse_error_count": 0}
        }
        res_halts = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_halts)
        assert res_halts["state"] == "HALTED"
        assert "Control plane policy or egress halt enforced" in res_halts["reason"]

        # 10. Authorization denials with verified integrity -> DEGRADED
        d_denials = {
            "status_flags": {"audit_data_available": True, "provenance_data_available": True},
            "audit_integrity": {"status": "VERIFIED"},
            "provenance_integrity": {"status": "VERIFIED"},
            "metrics": {"total_executions": 5, "authorization_denials": 3, "halts": 0, "execution_failures": 0, "parse_error_count": 0}
        }
        res_denials = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_denials)
        assert res_denials["state"] == "DEGRADED"
        assert "3 authorization denial(s)" in res_denials["reason"]

        # 11. Parse errors with verified integrity -> DEGRADED
        d_parse = {
            "status_flags": {"audit_data_available": True, "provenance_data_available": True},
            "audit_integrity": {"status": "VERIFIED"},
            "provenance_integrity": {"status": "VERIFIED"},
            "metrics": {"total_executions": 5, "authorization_denials": 0, "halts": 0, "execution_failures": 0, "parse_error_count": 4}
        }
        res_parse = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_parse)
        assert res_parse["state"] == "DEGRADED"
        assert "4 malformed log line(s)" in res_parse["reason"]

        # 12. Conflicting conditions: Corruption trumps halts and failures
        d_conflict_corrupt = {
            "status_flags": {"audit_data_available": True, "provenance_data_available": True},
            "audit_integrity": {"status": "CORRUPTED"},
            "provenance_integrity": {"status": "VERIFIED"},
            "metrics": {"total_executions": 5, "authorization_denials": 10, "halts": 5, "execution_failures": 2, "parse_error_count": 1}
        }
        res_conflict_corrupt = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_conflict_corrupt)
        assert res_conflict_corrupt["state"] == "BLOCKED"
        assert "Cryptographic integrity failure positively detected" in res_conflict_corrupt["reason"]

        # 13. Conflicting conditions: Failures trump halts
        d_conflict_fail_halt = {
            "status_flags": {"audit_data_available": True, "provenance_data_available": True},
            "audit_integrity": {"status": "VERIFIED"},
            "provenance_integrity": {"status": "VERIFIED"},
            "metrics": {"total_executions": 5, "authorization_denials": 10, "halts": 5, "execution_failures": 1, "parse_error_count": 1}
        }
        res_conflict_fail_halt = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_conflict_fail_halt)
        assert res_conflict_fail_halt["state"] == "BLOCKED"
        assert "Runtime execution failure(s) detected" in res_conflict_fail_halt["reason"]

        # 14. Conflicting conditions: Halts trump unverified state
        # Halts are a verified negative control event
        d_conflict_halt_unavail = {
            "status_flags": {"audit_data_available": False, "provenance_data_available": True},
            "audit_integrity": {"status": "UNAVAILABLE"},
            "provenance_integrity": {"status": "VERIFIED"},
            "metrics": {"total_executions": 5, "authorization_denials": 0, "halts": 2, "execution_failures": 0, "parse_error_count": 0}
        }
        res_conflict_halt_unavail = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_conflict_halt_unavail)
        assert res_conflict_halt_unavail["state"] == "HALTED"

        # 15. Malformed metric inputs: rejects strings like "abc" without coercing to zero
        d_malformed_metric = {
            "status_flags": {"audit_data_available": True, "provenance_data_available": True},
            "audit_integrity": {"status": "VERIFIED"},
            "provenance_integrity": {"status": "VERIFIED"},
            "metrics": {"total_executions": 5, "authorization_denials": "invalid_number", "halts": 0, "execution_failures": 0, "parse_error_count": 0}
        }
        res_malformed_metric = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_malformed_metric)
        assert res_malformed_metric["state"] == "DEGRADED"
        assert "malformed metric values detected" in res_malformed_metric["reason"]

        browser.close()
