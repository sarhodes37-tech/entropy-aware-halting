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
def test_system_state_matrix_and_ready_invariants(live_server):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(f"{live_server}/index.html")

        # Baseline Happy Path -> READY
        d_ready = {
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
        res_ready = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_ready)
        assert res_ready["state"] == "READY"
        assert "zero active operational exceptions" in res_ready["reason"]

        # --- REQUIREMENT 1: Missing Mandatory Operational Metrics PREVENTS READY ---
        mandatory_metrics = ["execution_failures", "halts", "authorization_denials", "parse_error_count"]

        # Test each individual missing metric when integrity is verified
        for metric in mandatory_metrics:
            m_copy = dict(d_ready["metrics"])
            m_copy[metric] = None
            d_missing_one = {**d_ready, "metrics": m_copy}
            res_missing_one = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_missing_one)
            assert res_missing_one["state"] == "UNVERIFIED", f"Expected UNVERIFIED when {metric} is None, got {res_missing_one['state']}"
            assert "Mandatory operational telemetry missing" in res_missing_one["reason"]
            assert metric in res_missing_one["reason"]

        # Test all four mandatory metrics missing
        d_missing_all = {
            **d_ready,
            "metrics": {
                "total_executions": 50,
                "execution_failures": None,
                "halts": None,
                "authorization_denials": None,
                "parse_error_count": None
            }
        }
        res_missing_all = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_missing_all)
        assert res_missing_all["state"] == "UNVERIFIED"
        assert "Mandatory operational telemetry missing" in res_missing_all["reason"]
        for metric in mandatory_metrics:
            assert metric in res_missing_all["reason"]

        # Test mixed valid and missing metrics
        d_mixed = {
            **d_ready,
            "metrics": {
                "total_executions": 50,
                "execution_failures": 0,
                "halts": None,
                "authorization_denials": 0,
                "parse_error_count": None
            }
        }
        res_mixed = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_mixed)
        assert res_mixed["state"] == "UNVERIFIED"
        assert "halts" in res_mixed["reason"]
        assert "parse_error_count" in res_mixed["reason"]
        assert "execution_failures" not in res_mixed["reason"]

        # Test invalid mandatory metric (malformed string)
        d_invalid_metric = {
            **d_ready,
            "metrics": {**d_ready["metrics"], "execution_failures": "malformed_string"}
        }
        res_invalid_metric = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_invalid_metric)
        assert res_invalid_metric["state"] == "UNVERIFIED"
        assert "Mandatory operational telemetry malformed" in res_invalid_metric["reason"]
        assert "execution_failures invalid" in res_invalid_metric["reason"]

        # --- REQUIREMENT 2: Validate Status Flag Types ---
        # Strings like "false" or "true" must NOT be accepted as boolean true
        bad_flags = ["false", "true", None, 1, 0, {}, []]
        for bad_val in bad_flags:
            d_bad_audit_flag = {
                **d_ready,
                "status_flags": {"audit_data_available": bad_val, "provenance_data_available": True}
            }
            res_bad_audit = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_bad_audit_flag)
            assert res_bad_audit["state"] == "UNVERIFIED", f"Expected UNVERIFIED for audit flag {bad_val}"
            assert "Audit Trail unavailable" in res_bad_audit["reason"]

            d_bad_prov_flag = {
                **d_ready,
                "status_flags": {"audit_data_available": True, "provenance_data_available": bad_val}
            }
            res_bad_prov = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_bad_prov_flag)
            assert res_bad_prov["state"] == "UNVERIFIED", f"Expected UNVERIFIED for prov flag {bad_val}"
            assert "Provenance Store unavailable" in res_bad_prov["reason"]

        # --- REQUIREMENT 3: State Precedence Rules ---
        # 1. Audit corrupted -> BLOCKED
        d_corrupt = {**d_ready, "audit_integrity": {"status": "CORRUPTED"}}
        res_corrupt = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_corrupt)
        assert res_corrupt["state"] == "BLOCKED"
        assert "Cryptographic integrity failure positively detected in Audit Trail" in res_corrupt["reason"]

        # 2. Operational failures -> BLOCKED
        d_fails = {**d_ready, "metrics": {**d_ready["metrics"], "execution_failures": 3}}
        res_fails = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_fails)
        assert res_fails["state"] == "BLOCKED"
        assert "Runtime execution failure(s) detected (3 failure(s))" in res_fails["reason"]

        # 3. Policy halts -> HALTED
        d_halts = {**d_ready, "metrics": {**d_ready["metrics"], "halts": 2}}
        res_halts = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_halts)
        assert res_halts["state"] == "HALTED"
        assert "Control plane policy or egress halt enforced (2 halt(s))" in res_halts["reason"]

        # 4. Denials only -> DEGRADED
        d_denials = {**d_ready, "metrics": {**d_ready["metrics"], "authorization_denials": 5}}
        res_denials = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_denials)
        assert res_denials["state"] == "DEGRADED"
        assert "5 authorization denial(s)" in res_denials["reason"]

        # 5. Parse errors only -> DEGRADED
        d_parse = {**d_ready, "metrics": {**d_ready["metrics"], "parse_error_count": 1}}
        res_parse = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_parse)
        assert res_parse["state"] == "DEGRADED"
        assert "1 malformed log line(s)" in res_parse["reason"]

        # 6. Precedence: Corruption beats halts and failures
        d_conflict_corrupt = {
            **d_ready,
            "audit_integrity": {"status": "CORRUPTED"},
            "metrics": {**d_ready["metrics"], "halts": 5, "execution_failures": 2}
        }
        res_conflict_corrupt = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_conflict_corrupt)
        assert res_conflict_corrupt["state"] == "BLOCKED"
        assert "Cryptographic integrity failure positively detected" in res_conflict_corrupt["reason"]

        # 7. Precedence: Failure beats halts
        d_conflict_fail = {
            **d_ready,
            "metrics": {**d_ready["metrics"], "halts": 5, "execution_failures": 2}
        }
        res_conflict_fail = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_conflict_fail)
        assert res_conflict_fail["state"] == "BLOCKED"
        assert "Runtime execution failure(s) detected" in res_conflict_fail["reason"]

        # 8. Precedence: Halts beat unverified telemetry
        d_conflict_halt_unavail = {
            **d_ready,
            "status_flags": {"audit_data_available": False, "provenance_data_available": True},
            "audit_integrity": {"status": "UNAVAILABLE"},
            "metrics": {**d_ready["metrics"], "halts": 2}
        }
        res_conflict_halt = page.evaluate("(d) => window.ObservatoryApp.deriveSystemState(d)", d_conflict_halt_unavail)
        assert res_conflict_halt["state"] == "HALTED"

        browser.close()
