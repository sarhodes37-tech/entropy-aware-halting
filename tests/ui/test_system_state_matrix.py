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
    ablation_file = tmp_path / "ablation_table.json"
    per_case_file = tmp_path / "per_case_results.json"

    audit_file.write_text("", encoding="utf-8")
    provenance_file.write_text("", encoding="utf-8")
    ablation_file.write_text("{}", encoding="utf-8")
    per_case_file.write_text("[]", encoding="utf-8")

    adapter = ObservatoryDataAdapter(
        audit_log_path=str(audit_file),
        provenance_log_path=str(provenance_file),
        ablation_table_path=str(ablation_file),
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
def test_system_state_epistemic_separation_of_dimensions(live_server):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(f"{live_server}/index.html")

        # Baseline: Both required logs verified, but NO live runtime health signal configured
        # Epistemic Rule: Historical verification does NOT independently establish live operational readiness!
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
        assert "live runtime operational health signal is not established" in res_no_live["reason"]

        # --- REQUIREMENT 1: Historical Counters Do Not Determine Current Operational State ---
        # A historical failure in logs does NOT mean current runtime is BLOCKED
        d_hist_failure = {
            **d_verified_no_live,
            "metrics": {**d_verified_no_live["metrics"], "execution_failures": 5}
        }
        res_hist_failure = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_hist_failure)
        assert res_hist_failure["state"] == "NOT ESTABLISHED"
        assert "live runtime operational health signal is not established" in res_hist_failure["reason"]

        # A historical policy halt in logs does NOT mean current runtime is HALTED
        d_hist_halt = {
            **d_verified_no_live,
            "metrics": {**d_verified_no_live["metrics"], "halts": 3}
        }
        res_hist_halt = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_hist_halt)
        assert res_hist_halt["state"] == "NOT ESTABLISHED"

        # A historical authorization denial does NOT mean system is DEGRADED
        d_hist_denial = {
            **d_verified_no_live,
            "metrics": {**d_verified_no_live["metrics"], "authorization_denials": 12}
        }
        res_hist_denial = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_hist_denial)
        assert res_hist_denial["state"] == "NOT ESTABLISHED"

        # --- REQUIREMENT 2: Cryptographic Integrity Corruption Produces BLOCKED ---
        # Corrupted audit log
        d_audit_corrupt = {
            **d_verified_no_live,
            "audit_integrity": {"status": "CORRUPTED"}
        }
        res_audit_corrupt = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_audit_corrupt)
        assert res_audit_corrupt["state"] == "BLOCKED"
        assert "Cryptographic integrity failure positively detected in Audit Trail" in res_audit_corrupt["reason"]

        # Corrupted provenance log
        d_prov_corrupt = {
            **d_verified_no_live,
            "provenance_integrity": {"status": "CORRUPTED"}
        }
        res_prov_corrupt = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_prov_corrupt)
        assert res_prov_corrupt["state"] == "BLOCKED"
        assert "Cryptographic integrity failure positively detected in Provenance Store" in res_prov_corrupt["reason"]

        # --- REQUIREMENT 3: Missing/Unavailable Integrity Telemetry Produces UNVERIFIED ---
        # Missing audit log
        d_missing_audit = {
            **d_verified_no_live,
            "status_flags": {"audit_data_available": False, "provenance_data_available": True},
            "audit_integrity": {"status": "UNAVAILABLE"}
        }
        res_missing_audit = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_missing_audit)
        assert res_missing_audit["state"] == "UNVERIFIED"
        assert "Audit Trail unavailable" in res_missing_audit["reason"]

        # Non-boolean flag (e.g. string "false") must be rejected as false -> UNVERIFIED
        d_bad_flag = {
            **d_verified_no_live,
            "status_flags": {"audit_data_available": "false", "provenance_data_available": True}
        }
        res_bad_flag = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_bad_flag)
        assert res_bad_flag["state"] == "UNVERIFIED"
        assert "Audit Trail unavailable" in res_bad_flag["reason"]

        # --- REQUIREMENT 4: Live Runtime Health Assertions ---
        # When live runtime health signal is present and HEALTHY/READY, and integrity is VERIFIED -> READY
        d_live_healthy = {
            **d_verified_no_live,
            "live_runtime_health": {"status": "HEALTHY", "source": "heartbeat_daemon"}
        }
        res_live_healthy = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_live_healthy)
        assert res_live_healthy["state"] == "READY"
        assert "Cryptographic integrity verified and live runtime health confirmed" in res_live_healthy["reason"]

        # When live runtime signal reports DEGRADED -> DEGRADED
        d_live_degraded = {
            **d_verified_no_live,
            "live_runtime_health": {"status": "DEGRADED", "reason": "Network latency anomaly"}
        }
        res_live_degraded = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_live_degraded)
        assert res_live_degraded["state"] == "DEGRADED"
        assert "Network latency anomaly" in res_live_degraded["reason"]

        # When live runtime signal reports HALTED -> HALTED
        d_live_halted = {
            **d_verified_no_live,
            "live_runtime_health": {"status": "HALTED", "reason": "Egress boundary containment active"}
        }
        res_live_halted = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_live_halted)
        assert res_live_halted["state"] == "HALTED"
        assert "Egress boundary containment active" in res_live_halted["reason"]

        # When live runtime signal reports BLOCKED -> BLOCKED
        d_live_blocked = {
            **d_verified_no_live,
            "live_runtime_health": {"status": "BLOCKED", "reason": "Runtime fault quarantined"}
        }
        res_live_blocked = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_live_blocked)
        assert res_live_blocked["state"] == "BLOCKED"
        assert "Runtime fault quarantined" in res_live_blocked["reason"]

        # Even if live health reports READY, if cryptographic integrity is corrupted, BLOCKED trumps READY
        d_corrupt_with_live = {
            **d_live_healthy,
            "audit_integrity": {"status": "CORRUPTED"}
        }
        res_corrupt_live = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_corrupt_with_live)
        assert res_corrupt_live["state"] == "BLOCKED"
        assert "Cryptographic integrity failure positively detected" in res_corrupt_live["reason"]

        browser.close()
