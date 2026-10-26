"""
Integration and security tests for EpistemicOS Observatory HTTP API Server.
"""

import json
import urllib.request
import urllib.error
import threading
import time
import pytest
from http import HTTPStatus

from epistemicos.ui.server import create_server, _is_verbose_logging_enabled, ObservatoryRequestHandler
from epistemicos.ui.adapters import ObservatoryDataAdapter


@pytest.fixture
def test_server(tmp_path):
    audit_file = tmp_path / "epistemic_audit.jsonl"
    provenance_file = tmp_path / "provenance_audit.jsonl"
    ablation_file = tmp_path / "ablation_table.json"
    per_case_file = tmp_path / "per_case_results.json"

    ablation_file.write_text(json.dumps({"baselines": {}}), encoding="utf-8")
    per_case_file.write_text(json.dumps([]), encoding="utf-8")

    adapter = ObservatoryDataAdapter(
        audit_log_path=str(audit_file),
        provenance_log_path=str(provenance_file),
        ablation_table_path=str(ablation_file),
        per_case_results_path=str(per_case_file)
    )

    static_dir = tmp_path / "static"
    static_dir.mkdir(parents=True, exist_ok=True)
    (static_dir / "index.html").write_text("<html><body>Observatory Test</body></html>", encoding="utf-8")
    (static_dir / "test.js").write_text("console.log('test');", encoding="utf-8")

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


def test_api_overview_route(test_server):
    req = urllib.request.urlopen(f"{test_server}/api/overview")
    assert req.status == HTTPStatus.OK
    assert req.headers.get("X-Frame-Options") == "DENY"
    assert req.headers.get("X-Content-Type-Options") == "nosniff"
    assert req.headers.get("Referrer-Policy") == "no-referrer"
    assert req.headers.get("Cache-Control") == "no-store, max-age=0"
    assert req.headers.get("X-Permitted-Cross-Domain-Policies") == "none"

    data = json.loads(req.read().decode("utf-8"))
    assert "metrics" in data
    assert "audit_integrity" in data


def test_api_provenance_route(test_server):
    req = urllib.request.urlopen(f"{test_server}/api/provenance")
    assert req.status == HTTPStatus.OK
    data = json.loads(req.read().decode("utf-8"))
    assert "disclaimer" in data
    assert "events" in data


def test_api_benchmarks_route(test_server):
    """Verifies that /api/benchmarks returns expected ablation_table and per_case_results structures."""
    req = urllib.request.urlopen(f"{test_server}/api/benchmarks")
    assert req.status == HTTPStatus.OK
    data = json.loads(req.read().decode("utf-8"))
    assert "ablation_table" in data
    assert "per_case_results" in data
    assert "available" in data["ablation_table"]
    assert "available" in data["per_case_results"]


def test_static_asset_serving(test_server):
    req = urllib.request.urlopen(f"{test_server}/index.html")
    assert req.status == HTTPStatus.OK
    assert "text/html" in req.headers.get("Content-Type")
    content = req.read().decode("utf-8")
    assert "Observatory Test" in content


def test_static_aria_accessibility_attributes():
    """Verify that the production index.html contains expected ARIA accessibility attributes and Trace / Provenance Explorer areas."""
    import pathlib
    index_path = pathlib.Path("epistemicos/ui/static/index.html")
    content = index_path.read_text(encoding="utf-8")
    assert 'aria-label="Observatory Navigation"' in content
    assert 'aria-label="Refresh overview metrics"' in content
    assert 'class="refresh-icon" aria-hidden="true"' in content
    assert 'type="search"' in content
    assert 'aria-label="Search execution traces by correlation or request ID"' in content
    assert 'aria-label="Filter execution traces by status"' in content
    assert 'id="trace-count"' in content
    assert 'aria-live="polite"' in content
    assert 'aria-atomic="true"' in content
    assert 'role="tabpanel"' in content
    assert 'aria-labelledby="tab-overview"' in content
    assert 'id="tab-overview"' in content
    assert 'tabindex="0"' in content
    assert 'id="overview-last-updated"' in content
    assert 'aria-live="polite"' in content
    assert 'id="metric-total-executions"' in content
    assert 'id="metric-parse-errors"' in content
    assert 'id="audit-data-availability"' in content
    assert 'id="provenance-data-availability"' in content
    assert 'id="overview-recent-traces"' in content
    assert 'aria-label="Recent Execution Traces"' in content
    assert 'aria-label="View Denied Requests"' in content
    assert 'aria-label="View Policy Halts"' in content
    assert '<span class="arrow" aria-hidden="true">➔</span>' in content
    # Trace Explorer area containers
    assert 'id="area-trace-list"' in content
    assert 'aria-label="Execution Trace List"' in content
    assert 'role="listbox"' in content
    assert 'aria-label="Select an execution trace"' in content
    # Provenance Explorer area containers and summary panels
    assert 'id="provenance-verification-grid"' in content
    assert 'id="summary-avail-badge"' in content
    assert 'id="summary-integrity-badge"' in content
    assert 'id="summary-coverage-badge"' in content
    assert 'id="summary-authenticity-badge"' in content
    assert 'id="provenance-findings-container"' in content
    assert 'id="area-provenance-list"' in content
    assert 'id="provenance-record-list"' in content
    assert 'id="provenance-inspector-content"' in content
    # Benchmark Workbench View 4 containers and controls
    assert 'id="view-benchmarks"' in content
    assert 'id="tab-benchmarks"' in content
    assert 'id="benchmark-run-summary-card"' in content
    assert 'id="summary-run-id"' in content
    assert 'id="summary-sample-count"' in content
    assert 'id="summary-dataset-digest"' in content
    assert 'id="summary-records-digest"' in content
    assert 'id="benchmark-baselines-tbody"' in content
    assert 'id="benchmark-mcnemar-tbody"' in content
    assert 'id="threshold-ablations-container"' in content
    assert 'id="benchmark-case-search"' in content
    assert 'id="benchmark-case-baseline-filter"' in content
    assert 'id="benchmark-case-outcome-filter"' in content
    assert 'id="benchmark-case-list"' in content
    assert 'id="benchmark-case-content"' in content
    assert 'id="attribution-container"' in content


def test_api_traces_routes(test_server):
    """Verify REST API trace listing and trace detail lookup routes."""
    # Test trace list
    req_list = urllib.request.urlopen(f"{test_server}/api/traces")
    assert req_list.status == HTTPStatus.OK
    traces = json.loads(req_list.read().decode("utf-8"))
    assert isinstance(traces, list)

    # Test trace lookup for non-existent ID
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(f"{test_server}/api/trace/missing_id_123")
    assert exc_info.value.code == HTTPStatus.NOT_FOUND


def test_read_only_method_restriction(test_server):
    """Verifies that non-GET methods (POST, PUT, DELETE, PATCH, HEAD, OPTIONS) are rejected with 405 Method Not Allowed."""
    methods = ["POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
    for method in methods:
        req = urllib.request.Request(f"{test_server}/api/overview", method=method)
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req)
        assert exc_info.value.code == HTTPStatus.METHOD_NOT_ALLOWED


def test_directory_traversal_prevention(test_server):
    """Adversarial test: verifies that directory traversal and null-byte attempts are blocked."""
    traversal_paths = [
        "/../../../../etc/passwd",
        "/..%2f..%2f..%2fetc%2fpasswd",
        "/%2e%2e/%2e%2e/etc/passwd",
        "/%252e%252e/%252e%252e/etc/passwd",
        "/api/../../epistemicos/audit.py",
        "/index.html%00.txt"
    ]
    for path in traversal_paths:
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(f"{test_server}{path}")
        assert exc_info.value.code in (HTTPStatus.BAD_REQUEST, HTTPStatus.FORBIDDEN, HTTPStatus.NOT_FOUND)


def test_trace_lookup_sanitizes_credentials_in_error_response(test_server):
    """Verifies that credentials in requested trace parameters are redacted in 404 responses."""
    sensitive_param = "sk-123456789012345678901234"
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(f"{test_server}/api/trace/{sensitive_param}")

    assert exc_info.value.code == HTTPStatus.NOT_FOUND
    body = exc_info.value.read().decode("utf-8")
    data = json.loads(body)
    assert sensitive_param not in body
    assert data["error"] == "Trace not found: sk-[REDACTED]"


def test_static_file_error_handling_does_not_leak_exception_details(test_server, monkeypatch):
    """Verifies that static file read errors return a generic message without leaking system details."""
    def mock_open(*args, **kwargs):
        raise PermissionError("[Errno 13] Permission denied: '/etc/shadow'")

    monkeypatch.setattr("builtins.open", mock_open)

    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(f"{test_server}/index.html")

    assert exc_info.value.code == HTTPStatus.INTERNAL_SERVER_ERROR
    body = exc_info.value.read().decode("utf-8")
    data = json.loads(body)
    assert data["error"] == "Failed to read file"
    assert "/etc/shadow" not in body
    assert "Permission denied" not in body


def test_verbose_logging_environment_variable_validation(monkeypatch):
    """Verifies safe validation and parsing of the VERBOSE_OBSERVATORY environment variable."""
    # Test truthy values
    truthy_values = ["1", "true", "TRUE", " 1 ", "yes", "ON", "enabled"]
    for val in truthy_values:
        monkeypatch.setenv("VERBOSE_OBSERVATORY", val)
        assert _is_verbose_logging_enabled() is True

    # Test falsy / invalid values
    falsy_values = ["0", "false", "FALSE", "", "2", "invalid", "no", "off"]
    for val in falsy_values:
        monkeypatch.setenv("VERBOSE_OBSERVATORY", val)
        assert _is_verbose_logging_enabled() is False

    # Test unset
    monkeypatch.delenv("VERBOSE_OBSERVATORY", raising=False)
    assert _is_verbose_logging_enabled() is False


def test_log_message_behavior_with_verbose_env(monkeypatch):
    """Verifies that log_message delegates to super class only when VERBOSE_OBSERVATORY is safely set."""
    calls = []

    def mock_super_log(self, format_str, *args):
        calls.append((format_str, args))

    monkeypatch.setattr("http.server.BaseHTTPRequestHandler.log_message", mock_super_log)

    handler = ObservatoryRequestHandler.__new__(ObservatoryRequestHandler)

    # When env is falsy
    monkeypatch.setenv("VERBOSE_OBSERVATORY", "0")
    handler.log_message("Test %s", "arg")
    assert len(calls) == 0

    # When env is truthy
    monkeypatch.setenv("VERBOSE_OBSERVATORY", "1")
    handler.log_message("Test %s", "arg")
    assert len(calls) == 1
    assert calls[0] == ("Test %s", ("arg",))


def test_observatory_concept_image_and_readme_integration():
    """Verifies that docs/figures/observatory-concept.png exists and is referenced in README.md with appropriate disclaimer."""
    import pathlib
    concept_img_path = pathlib.Path("docs/figures/observatory-concept.png")
    assert concept_img_path.exists(), "observatory-concept.png image asset missing"

    readme_path = pathlib.Path("README.md")
    content = readme_path.read_text(encoding="utf-8")
    assert "docs/figures/observatory-concept.png" in content
    assert "illustrative design concept" in content.lower()
    assert "do not represent live system telemetry" in content.lower()


def test_observatory_css_design_foundation_tokens():
    """Verifies that style.css contains the expected dark graphite and cyan design foundation tokens."""
    import pathlib
    css_path = pathlib.Path("epistemicos/ui/static/style.css")
    css_content = css_path.read_text(encoding="utf-8")
    assert "--bg-base: #0d1117;" in css_content
    assert "--bg-surface: #161b22;" in css_content
    assert "--accent-primary: #38bdf8;" in css_content
    assert "--status-verified-fg: #2dd4bf;" in css_content
    assert "--status-failed-fg: #fb7185;" in css_content


def test_recent_traces_row_keyboard_accessibility():
    """Verifies that app.js sets tabindex, role='button', aria-label, and keydown handlers for clickable table rows."""
    import pathlib
    js_path = pathlib.Path("epistemicos/ui/static/app.js")
    js_content = js_path.read_text(encoding="utf-8")
    assert "tr.setAttribute('tabindex', '0');" in js_content
    assert "tr.setAttribute('role', 'button');" in js_content
    assert "tr.setAttribute('aria-label', `Inspect execution trace" in js_content
    assert "tr.setAttribute('aria-selected', isSelectedEvent ? 'true' : 'false');" in js_content
    assert "e.key === 'Enter' || e.key === ' '" in js_content

    css_path = pathlib.Path("epistemicos/ui/static/style.css")
    css_content = css_path.read_text(encoding="utf-8")
    assert ".data-table tr.clickable:focus-visible" in css_content
    assert ".data-table tr.clickable.selected" in css_content


def test_copy_to_clipboard_dynamic_aria_accessibility_update():
    """Verifies that app.js captures original aria-label and dynamically updates aria-label during clipboard copy feedback."""
    import pathlib
    js_path = pathlib.Path("epistemicos/ui/static/app.js")
    js_content = js_path.read_text(encoding="utf-8")
    assert "const origAriaLabel = btnElement ? btnElement.getAttribute('aria-label') : null;" in js_content
    assert "btnElement.setAttribute('aria-label', 'Copied to clipboard!');" in js_content
    assert "btnElement.setAttribute('aria-label', 'Copy failed');" in js_content
    assert "btnElement.setAttribute('aria-label', 'Copy unavailable');" in js_content
    assert "restoreState" in js_content


def test_dynamic_buttons_aria_accessibility_completeness():
    """Verifies that dynamically created retry buttons and copy buttons in app.js have explicit aria-label attributes."""
    import pathlib
    js_path = pathlib.Path("epistemicos/ui/static/app.js")
    js_content = js_path.read_text(encoding="utf-8")
    assert "retryBtn.setAttribute('aria-label', 'Retry loading execution traces');" in js_content
    assert "retryBtn.setAttribute('aria-label', 'Retry loading provenance records');" in js_content
    assert "retryBtn.setAttribute('aria-label', 'Retry loading benchmark artifacts');" in js_content
    assert "copyCorrBtn.setAttribute('aria-label', 'Copy Correlation ID');" in js_content
    assert '<span class="arrow" aria-hidden="true">➔</span>' in js_content
