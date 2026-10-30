"""
Playwright E2E and visual verification test suite for Trace Explorer mobile drill-in navigation,
lifecycle timeline sequence visualization, and evidence inspector across viewports.
"""

import json
import time
import threading
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
def e2e_server(tmp_path):
    audit_file = tmp_path / "epistemic_audit.jsonl"
    provenance_file = tmp_path / "provenance_audit.jsonl"
    ablation_file = tmp_path / "ablation_table.json"
    per_case_file = tmp_path / "per_case_results.json"

    ablation_file.write_text(json.dumps({"baselines": {}}), encoding="utf-8")
    per_case_file.write_text(json.dumps([]), encoding="utf-8")

    # Sample mock trace provenance events including sequence 0 and XSS payload
    sample_events = [
        {
            "event_id": "pe_000",
            "sequence_number": 0,
            "timestamp": "2025-01-15T09:59:59Z",
            "event_type": "ACTION_PROPOSED",
            "provenance_source": "EpistemicOrchestrator",
            "correlation_id": "corr_<script>alert('xss')</script>_100",
            "request_id": "req_100",
            "action_name": "read_table",
            "target": "/database/users",
            "prev_hash": None,
            "entry_hash": "a0b1c2d3e4f56789012345678901234567890123456789012345678901234567"
        },
        {
            "event_id": "pe_001",
            "sequence_number": 1,
            "timestamp": "2025-01-15T10:00:00Z",
            "event_type": "AUTHORIZATION_GRANTED",
            "provenance_source": "AuthorizationAuthority",
            "correlation_id": "corr_<script>alert('xss')</script>_100",
            "request_id": "req_100",
            "action_name": "read_table",
            "target": "/database/users",
            "authorization_token_id": "cap_tok_abc123",
            "canonical_request_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "policy_version": "v1.2.0",
            "prev_hash": "a0b1c2d3e4f56789012345678901234567890123456789012345678901234567",
            "entry_hash": "b2c3d4e5f6a17890123456789012345678901234567890123456789012345678"
        },
        {
            "event_id": "pe_002",
            "sequence_number": 2,
            "timestamp": "2025-01-15T10:00:01Z",
            "event_type": "EXECUTION_STARTED",
            "provenance_source": "TrustedExecutionBoundary",
            "correlation_id": "corr_<script>alert('xss')</script>_100",
            "request_id": "req_100",
            "action_name": "read_table",
            "target": "/database/users",
            "authorization_token_id": "cap_tok_abc123",
            "prev_hash": "b2c3d4e5f6a17890123456789012345678901234567890123456789012345678",
            "entry_hash": "c3d4e5f6a1b27890123456789012345678901234567890123456789012345678"
        },
        {
            "event_id": "pe_003",
            "sequence_number": 3,
            "timestamp": "2025-01-15T10:00:02Z",
            "event_type": "EXECUTION_SUCCEEDED",
            "provenance_source": "TrustedExecutionBoundary",
            "correlation_id": "corr_<script>alert('xss')</script>_100",
            "request_id": "req_100",
            "action_name": "read_table",
            "target": "/database/users",
            "prev_hash": "c3d4e5f6a1b27890123456789012345678901234567890123456789012345678",
            "entry_hash": "d4e5f6a1b2c37890123456789012345678901234567890123456789012345678"
        }
    ]

    with open(provenance_file, "w", encoding="utf-8") as f:
        for ev in sample_events:
            f.write(json.dumps(ev) + "\n")

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
def test_mobile_trace_explorer_drilldown_navigation(e2e_server, tmp_path):
    """E2E test verifying mobile drill-in navigation, lifecycle visualization, evidence inspector, safe DOM rendering, and viewports."""
    viewports = [
        {"width": 360, "height": 740},
        {"width": 390, "height": 844},
        {"width": 430, "height": 932},
        {"width": 768, "height": 1024},
        {"width": 1024, "height": 768},
        {"width": 1440, "height": 900}
    ]

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)

        for vp in viewports:
            context = browser.new_context(viewport=vp)
            page = context.new_page()

            # Track dialog events to assert no XSS scripts execute
            dialogs = []
            page.on("dialog", lambda d: dialogs.append(d.message))

            page.goto(f"{e2e_server}/index.html")

            # Click Execution Traces tab
            page.click("#tab-traces")
            page.wait_for_selector("#trace-list .trace-item")

            # Verify trace item is visible
            trace_item = page.locator("#trace-list .trace-item").first
            assert trace_item.is_visible()

            # Click trace item to drill in
            trace_item.click()
            page.wait_for_selector(".lifecycle-timeline")

            # Verify no script dialog executed
            assert len(dialogs) == 0

            # On mobile (<1024px), verify Back button is visible and trace detail is shown
            if vp["width"] < 1024:
                btn_back = page.locator("#btn-trace-back-to-list")
                assert btn_back.is_visible()

                # Verify safe DOM breadcrumb renders raw text without executing script
                breadcrumb_text = page.locator("#trace-breadcrumb").text_content()
                assert "corr_<script>alert('xss')</script>_100" in breadcrumb_text

                # Verify lifecycle sequence card is present (4 events including sequence 0)
                assert page.locator(".lifecycle-stage").count() == 4

                # Select stage #0 (ACTION_PROPOSED)
                stage_card_0 = page.locator(".lifecycle-stage-card").nth(0)
                stage_card_0.click()

                # Verify Evidence Inspector appears
                page.wait_for_selector("#area-evidence-inspector")
                assert page.locator("#area-evidence-inspector").is_visible()

                # Select stage #1 (AUTHORIZATION_GRANTED)
                stage_card_1 = page.locator(".lifecycle-stage-card").nth(1)
                stage_card_1.click()

                # Verify Back to Lifecycle button is visible
                btn_back_detail = page.locator("#btn-trace-back-to-detail")
                assert btn_back_detail.is_visible()

                # Click Back to Lifecycle
                btn_back_detail.click()
                assert page.locator("#btn-trace-back-to-list").is_visible()

                # Click Back to Traces
                btn_back.click()
                assert page.locator("#area-trace-list").is_visible()

            else:
                # On Desktop (>=1024px), verify both list and detail are simultaneously visible
                assert page.locator("#area-trace-list").is_visible()
                assert page.locator("#view-traces .trace-detail-container").is_visible()

            context.close()

        browser.close()
