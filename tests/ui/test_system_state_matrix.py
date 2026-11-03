import json
import threading
import time
from pathlib import Path
import pytest
from epistemicos.ui.server import create_server
from epistemicos.ui.adapters import ObservatoryDataAdapter

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


@pytest.fixture(scope="module")
def live_server(tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp("state_matrix_server")
    audit_file = tmp_path / "epistemic_audit.jsonl"
    provenance_file = tmp_path / "provenance_audit.jsonl"
    ablation_table_file = tmp_path / "ablation_table.json"
    per_case_file = tmp_path / "per_case_results.json"

    audit_file.write_text("", encoding="utf-8")
    provenance_file.write_text("", encoding="utf-8")
    ablation_table_file.write_text("{}", encoding="utf-8")
    per_case_file.write_text("[]", encoding="utf-8")

    adapter = ObservatoryDataAdapter(
        audit_log_path=str(audit_file),
        provenance_log_path=str(provenance_file),
        ablation_table_path=str(ablation_table_file),
        per_case_results_path=str(per_case_file)
    )

    static_dir = Path(__file__).parent.parent.parent / "epistemicos" / "ui" / "static"
    server = create_server(host="127.0.0.1", port=0, adapter=adapter, static_dir=str(static_dir))
    port = server.server_port

    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    time.sleep(0.1)

    base_url = f"http://127.0.0.1:{port}"
    yield base_url

    server.shutdown()
    server.server_close()


@pytest.mark.skipif(not PLAYWRIGHT_AVAILABLE, reason="playwright not installed")
def test_metric_and_boolean_normalization(live_server):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(f"{live_server}/index.html")

        # normalizeMetricValue testing
        assert page.evaluate("() => window.ObservatoryApp.normalizeMetricValue(0)") == {"status": "VALID", "value": 0}
        assert page.evaluate("() => window.ObservatoryApp.normalizeMetricValue(123)") == {"status": "VALID", "value": 123}
        assert page.evaluate("() => window.ObservatoryApp.normalizeMetricValue('456')") == {"status": "VALID", "value": 456}
        assert page.evaluate("() => window.ObservatoryApp.normalizeMetricValue('0')") == {"status": "VALID", "value": 0}

        # Null / Undefined
        assert page.evaluate("() => window.ObservatoryApp.normalizeMetricValue(null)") == {"status": "UNAVAILABLE", "value": None}
        assert page.evaluate("() => window.ObservatoryApp.normalizeMetricValue(undefined)") == {"status": "UNAVAILABLE", "value": None}

        # Invalid: empty string, booleans, negative numbers, floats, NaN, non-numeric strings, objects
        assert page.evaluate("() => window.ObservatoryApp.normalizeMetricValue('')") == {"status": "INVALID", "value": None}
        assert page.evaluate("() => window.ObservatoryApp.normalizeMetricValue(true)") == {"status": "INVALID", "value": None}
        assert page.evaluate("() => window.ObservatoryApp.normalizeMetricValue(false)") == {"status": "INVALID", "value": None}
        assert page.evaluate("() => window.ObservatoryApp.normalizeMetricValue(-1)") == {"status": "INVALID", "value": None}
        assert page.evaluate("() => window.ObservatoryApp.normalizeMetricValue('-5')") == {"status": "INVALID", "value": None}
        assert page.evaluate("() => window.ObservatoryApp.normalizeMetricValue(3.14)") == {"status": "INVALID", "value": None}
        assert page.evaluate("() => window.ObservatoryApp.normalizeMetricValue('abc')") == {"status": "INVALID", "value": None}
        assert page.evaluate("() => window.ObservatoryApp.normalizeMetricValue({})") == {"status": "INVALID", "value": None}
        assert page.evaluate("() => window.ObservatoryApp.normalizeMetricValue([])") == {"status": "INVALID", "value": None}

        # normalizeBooleanFlag testing
        assert page.evaluate("() => window.ObservatoryApp.normalizeBooleanFlag(true)") is True
        assert page.evaluate("() => window.ObservatoryApp.normalizeBooleanFlag(false)") is False
        assert page.evaluate("() => window.ObservatoryApp.normalizeBooleanFlag('true')") is False
        assert page.evaluate("() => window.ObservatoryApp.normalizeBooleanFlag('false')") is False
        assert page.evaluate("() => window.ObservatoryApp.normalizeBooleanFlag(1)") is False
        assert page.evaluate("() => window.ObservatoryApp.normalizeBooleanFlag(0)") is False
        assert page.evaluate("() => window.ObservatoryApp.normalizeBooleanFlag(null)") is False
        assert page.evaluate("() => window.ObservatoryApp.normalizeBooleanFlag(undefined)") is False
        assert page.evaluate("() => window.ObservatoryApp.normalizeBooleanFlag({})") is False

        browser.close()


@pytest.mark.skipif(not PLAYWRIGHT_AVAILABLE, reason="playwright not installed")
def test_cumulative_exception_completeness(live_server):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(f"{live_server}/index.html")

        # 1. Complete availability: all 4 required counters valid -> COMPLETE, accurate sum
        m_complete = {
            "authorization_denials": 5,
            "halts": 2,
            "execution_failures": 1,
            "parse_error_count": 0
        }
        res_comp = page.evaluate("(m) => window.ObservatoryApp.calculateCumulativeExceptions(m)", m_complete)
        assert res_comp["status"] == "COMPLETE"
        assert res_comp["total"] == 8
        assert res_comp["missing"] == []
        assert res_comp["invalid"] == []

        # 2. All unavailable -> UNAVAILABLE
        m_all_unavail = {
            "authorization_denials": None,
            "halts": None,
            "execution_failures": None,
            "parse_error_count": None
        }
        res_all_unavail = page.evaluate("(m) => window.ObservatoryApp.calculateCumulativeExceptions(m)", m_all_unavail)
        assert res_all_unavail["status"] == "UNAVAILABLE"
        assert res_all_unavail["total"] is None
        assert len(res_all_unavail["missing"]) == 4

        # 3. Partial availability: some valid, some unavailable -> PARTIAL (never presented as complete sum)
        m_partial = {
            "authorization_denials": 5,
            "halts": None,
            "execution_failures": 1,
            "parse_error_count": None
        }
        res_part = page.evaluate("(m) => window.ObservatoryApp.calculateCumulativeExceptions(m)", m_partial)
        assert res_part["status"] == "PARTIAL"
        assert res_part["total"] is None
        assert res_part["partialSum"] == 6
        assert "Policy Halts" in res_part["missing"]
        assert "Parse Errors" in res_part["missing"]
        assert "missing Policy Halts, Parse Errors" in res_part["reason"]

        # 4. Malformed input: any counter invalid -> MALFORMED
        m_malformed = {
            "authorization_denials": 5,
            "halts": "invalid_string",
            "execution_failures": 1,
            "parse_error_count": 0
        }
        res_malformed = page.evaluate("(m) => window.ObservatoryApp.calculateCumulativeExceptions(m)", m_malformed)
        assert res_malformed["status"] == "MALFORMED"
        assert res_malformed["total"] is None
        assert "Policy Halts" in res_malformed["invalid"]
        assert "Malformed counter data detected in: Policy Halts" in res_malformed["reason"]

        browser.close()


@pytest.mark.skipif(not PLAYWRIGHT_AVAILABLE, reason="playwright not installed")
def test_system_state_epistemic_separation_and_live_contract(live_server):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(f"{live_server}/index.html")

        # Baseline: Both required logs verified, but NO live runtime health signal configured
        # Normal adapter output -> NOT ESTABLISHED (never READY)
        d_verified_no_live = {
            "status_flags": {"audit_data_available": True, "provenance_data_available": True},
            "audit_integrity": {"status": "VERIFIED"},
            "provenance_integrity": {"status": "VERIFIED"},
            "metrics": {
                "total_executions": 100,
                "authorization_denials": 0,
                "halts": 0,
                "execution_failures": 0,
                "parse_error_count": 0
            }
        }
        res_no_live = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_verified_no_live)
        assert res_no_live["state"] == "NOT ESTABLISHED"
        assert "authoritative live runtime operational health attestation is not established" in res_no_live["reason"]
        assert res_no_live["state"] != "READY"

        # --- Negative Tests for Live Health Trust Boundary ---
        # 1. A source string plus HEALTHY is insufficient to produce READY
        d_source_string = {
            **d_verified_no_live,
            "live_runtime_health": {"status": "HEALTHY", "source": "systemd_watchdog_supervisor"}
        }
        res_source = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_source_string)
        assert res_source["state"] == "NOT ESTABLISHED"
        assert res_source["state"] != "READY"
        assert res_source["details"]["liveHealth"] == "UNAUTHENTICATED_SIGNAL_REJECTED"

        # 2. A stale timestamp is insufficient to produce READY
        d_stale = {
            **d_verified_no_live,
            "live_runtime_health": {
                "status": "HEALTHY",
                "source": "supervisor",
                "observed_at": "2020-01-01T00:00:00Z"
            }
        }
        res_stale = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_stale)
        assert res_stale["state"] == "NOT ESTABLISHED"
        assert res_stale["state"] != "READY"

        # 3. An unsigned or invalidly signed attestation is insufficient to produce READY
        d_unsigned = {
            **d_verified_no_live,
            "live_runtime_health": {
                "status": "HEALTHY",
                "source": "supervisor",
                "signature": "invalid_or_untrusted_signature"
            }
        }
        res_unsigned = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_unsigned)
        assert res_unsigned["state"] == "NOT ESTABLISHED"
        assert res_unsigned["state"] != "READY"

        # 4. Historical counters do NOT falsely induce BLOCKED, HALTED, or DEGRADED
        d_hist_failure = {
            **d_verified_no_live,
            "metrics": {**d_verified_no_live["metrics"], "execution_failures": 5}
        }
        res_hist_failure = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_hist_failure)
        assert res_hist_failure["state"] == "NOT ESTABLISHED"

        d_hist_halt = {
            **d_verified_no_live,
            "metrics": {**d_verified_no_live["metrics"], "halts": 3}
        }
        res_hist_halt = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_hist_halt)
        assert res_hist_halt["state"] == "NOT ESTABLISHED"

        # 5. Cryptographic integrity corruption evaluates to BLOCKED
        d_corrupt = {
            **d_verified_no_live,
            "audit_integrity": {"status": "CORRUPTED"}
        }
        res_corrupt = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_corrupt)
        assert res_corrupt["state"] == "BLOCKED"
        assert "Cryptographic integrity failure positively detected in Audit Trail" in res_corrupt["reason"]

        browser.close()
