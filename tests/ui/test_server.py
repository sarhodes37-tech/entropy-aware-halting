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

from epistemicos.ui.server import create_server
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

    data = json.loads(req.read().decode("utf-8"))
    assert "metrics" in data
    assert "audit_integrity" in data


def test_api_provenance_route(test_server):
    req = urllib.request.urlopen(f"{test_server}/api/provenance")
    assert req.status == HTTPStatus.OK
    data = json.loads(req.read().decode("utf-8"))
    assert "disclaimer" in data
    assert "events" in data


def test_static_asset_serving(test_server):
    req = urllib.request.urlopen(f"{test_server}/index.html")
    assert req.status == HTTPStatus.OK
    assert "text/html" in req.headers.get("Content-Type")
    content = req.read().decode("utf-8")
    assert "Observatory Test" in content


def test_static_aria_accessibility_attributes():
    """Verify that the production index.html contains expected ARIA accessibility attributes."""
    import pathlib
    index_path = pathlib.Path("epistemicos/ui/static/index.html")
    content = index_path.read_text(encoding="utf-8")
    assert 'aria-label="Observatory Navigation"' in content
    assert 'aria-label="Refresh overview metrics"' in content
    assert 'class="refresh-icon" aria-hidden="true"' in content
    assert 'aria-label="Search execution traces by correlation or request ID"' in content
    assert 'aria-label="Filter execution traces by status"' in content
    assert 'role="tabpanel"' in content
    assert 'aria-labelledby="tab-overview"' in content
    assert 'id="tab-overview"' in content
    assert 'tabindex="0"' in content


def test_read_only_method_restriction(test_server):
    """Verifies that non-GET methods (POST, PUT, DELETE) are rejected with 405 Method Not Allowed."""
    methods = ["POST", "PUT", "DELETE"]
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
