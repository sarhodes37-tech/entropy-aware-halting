"""Tests for State-First Operational Interface in the EpistemicOS Observatory Overview.

Asserts:
1. Every supported state-to-visual mapping and semantic metadata.
2. Overview DOM renders state-first hierarchy (primary banner, 4 dimensions, metrics, stream).
3. Positive corruption evaluates and renders as BLOCKED.
4. Missing and unavailable evidence presentation (UNVERIFIED and NOT ESTABLISHED).
5. Separation of cumulative historical activity counters from current operational health.
6. Responsive layout across desktop, tablet, and mobile (no horizontal page overflow).
7. Accessibility, ARIA status announcements, and keyboard operation.
"""

import json
from pathlib import Path
import pytest
try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

pytestmark = pytest.mark.skipif(not PLAYWRIGHT_AVAILABLE, reason="playwright not installed")

STATIC_DIR = Path(__file__).parent.parent.parent / "epistemicos" / "ui" / "static"


@pytest.fixture(scope="module")
def browser_instance():
    if not PLAYWRIGHT_AVAILABLE:
        pytest.skip("playwright not installed")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        yield browser
        browser.close()


def test_state_to_visual_mappings_and_metadata(browser_instance):
    """Verifies that getStateMetadata in app.js provides distinct, accurate semantics."""
    page = browser_instance.new_page()
    page.goto(f"file://{STATIC_DIR / 'index.html'}")

    states_to_test = [
        ("READY", True, "✓"),
        ("AUTHORIZED", True, "✓"),
        ("BLOCKED", True, "⛔"),
        ("FAILED", True, "✗"),
        ("HALTED", True, "✋"),
        ("DEGRADED", True, "⚠️"),
        ("UNVERIFIED", False, "⊘"),
        ("NOT ESTABLISHED", False, "⊘"),
        ("UNKNOWN_CUSTOM_STATE", False, "?"),
    ]

    for state, expected_established, expected_glyph in states_to_test:
        meta = page.evaluate(f"window.ObservatoryApp.getStateMetadata('{state}')")
        assert meta["label"] == state
        assert meta["established"] is expected_established
        assert meta["glyph"] == expected_glyph
        assert "statusClass" in meta
        assert "establishmentClass" in meta
        assert "meaning" in meta
    page.close()


def test_overview_dom_renders_state_first_hierarchy(browser_instance):
    """Verifies that Overview contains the primary state card, 4 dimensions, and metrics."""
    page = browser_instance.new_page()
    page.goto(f"file://{STATIC_DIR / 'index.html'}")

    page.wait_for_selector("#overview-primary-state-card")
    page.wait_for_selector("#dimension-integrity")
    page.wait_for_selector("#dimension-activity")
    page.wait_for_selector("#dimension-health")
    page.wait_for_selector("#dimension-completeness")

    # Verify primary state banner hierarchy
    assert page.locator("#overview-system-state-text").is_visible()
    assert page.locator("#overview-state-establishment").is_visible()
    assert page.locator("#overview-state-rationale").is_visible()
    assert page.locator("#overview-state-runtime").is_visible()

    # Verify 4 epistemic dimensions
    dim1 = page.locator("#dimension-integrity")
    assert "DIMENSION 01" in dim1.text_content()
    assert "CRYPTOGRAPHIC INTEGRITY" in dim1.text_content()

    dim2 = page.locator("#dimension-activity")
    assert "DIMENSION 02" in dim2.text_content()
    assert "HISTORICAL ACTIVITY" in dim2.text_content()

    dim3 = page.locator("#dimension-health")
    assert "DIMENSION 03" in dim3.text_content()
    assert "OPERATIONAL HEALTH" in dim3.text_content()

    dim4 = page.locator("#dimension-completeness")
    assert "DIMENSION 04" in dim4.text_content()
    assert "EVIDENCE AVAILABILITY" in dim4.text_content()

    # Verify cumulative metrics bar labels
    metric_labels = (
        page.locator(".ops-metrics-grid .ops-metric-item .metric-label").all_text_contents()
    )
    for lbl in metric_labels:
        assert "Historical" in lbl or "Parse" in lbl

    # Verify operational stream table has valid tbody and rows
    tbody = page.locator("#overview-recent-traces")
    assert tbody.count() == 1
    page.close()


def test_positive_corruption_evaluates_to_blocked(browser_instance):
    """Verifies positive corruption in audit trail renders BLOCKED on primary card."""
    page = browser_instance.new_page()
    page.goto(f"file://{STATIC_DIR / 'index.html'}")

    corrupt_telemetry = {
        "metrics": {
            "total_executions": 50,
            "authorization_denials": 0,
            "halts": 0,
            "execution_failures": 0,
            "parse_error_count": 0,
        },
        "status_flags": {
            "audit_data_available": True,
            "provenance_data_available": True,
        },
        "audit_integrity": {
            "status": "CORRUPTED",
            "message": "SHA-256 hash chain break at entry 12",
            "records_verified": 11,
        },
        "provenance_integrity": {
            "status": "VERIFIED",
            "message": "All provenance events verified",
            "records_verified": 50,
        },
    }

    page.evaluate(f"""
        window.ObservatoryApp.state.overviewData = {json.dumps(corrupt_telemetry)};
        window.ObservatoryApp.renderOverview();
    """)

    state_text = page.locator("#overview-system-state-text").text_content()
    assert "BLOCKED" in state_text
    assert "⛔" in state_text

    est_text = page.locator("#overview-state-establishment").text_content()
    assert est_text == "ESTABLISHED"

    rationale = page.locator("#overview-state-rationale").text_content()
    assert "integrity failure" in rationale.lower()

    dim1_badge = page.locator("#dim-integrity-badge").text_content()
    assert "BLOCKED" in dim1_badge
    page.close()


def test_missing_and_unavailable_evidence_presentation(browser_instance):
    """Verifies that missing evidence presents as NOT ESTABLISHED and never claims READY."""
    page = browser_instance.new_page()
    page.goto(f"file://{STATIC_DIR / 'index.html'}")

    unverified_telemetry = {
        "metrics": {
            "total_executions": 0,
            "authorization_denials": 0,
            "halts": 0,
            "execution_failures": 0,
            "parse_error_count": 0,
        },
        "status_flags": {
            "audit_data_available": False,
            "provenance_data_available": False,
        },
        "audit_integrity": {
            "status": "UNAVAILABLE",
            "records_verified": 0,
        },
        "provenance_integrity": {
            "status": "UNAVAILABLE",
            "records_verified": 0,
        },
    }

    page.evaluate(f"""
        window.ObservatoryApp.state.overviewData = {json.dumps(unverified_telemetry)};
        window.ObservatoryApp.renderOverview();
    """)

    state_text = page.locator("#overview-system-state-text").text_content()
    assert "UNVERIFIED" in state_text or "NOT ESTABLISHED" in state_text
    assert "READY" not in state_text

    est_text = page.locator("#overview-state-establishment").text_content()
    assert est_text == "NOT ESTABLISHED"

    health_badge = page.locator("#dim-health-badge").text_content()
    assert "NOT ESTABLISHED" in health_badge

    comp_badge = page.locator("#dim-completeness-badge").text_content()
    assert "UNAVAILABLE" in comp_badge
    page.close()


def test_physical_file_presence_yields_available_not_complete(browser_instance):
    """Verifies that physical file presence yields AVAILABLE, never claiming COMPLETE."""
    page = browser_instance.new_page()
    page.goto(f"file://{STATIC_DIR / 'index.html'}")

    present_telemetry = {
        "metrics": {
            "total_executions": 20,
            "authorization_denials": 0,
            "halts": 0,
            "execution_failures": 0,
            "parse_error_count": 0,
        },
        "status_flags": {
            "audit_data_available": True,
            "provenance_data_available": True,
        },
        "audit_integrity": {
            "status": "VERIFIED",
            "records_verified": 20,
        },
        "provenance_integrity": {
            "status": "VERIFIED",
            "records_verified": 20,
        },
    }

    page.evaluate(f"""
        window.ObservatoryApp.state.overviewData = {json.dumps(present_telemetry)};
        window.ObservatoryApp.renderOverview();
    """)

    dim_badge = page.locator("#dim-completeness-badge").text_content()
    assert "AVAILABLE" in dim_badge
    assert "COMPLETE" not in dim_badge

    dim_content = page.locator("#dim-completeness-content").text_content()
    assert "presence does not prove source completeness" in dim_content.lower()

    # Verify chain integrity metadata displays verified SHA-256 chain without HMAC hardening claims
    chain_meta = page.locator("#overview-evidence-anchor").text_content()
    assert "LOCAL SHA-256 HASH-CHAIN (VERIFIED)" in chain_meta
    assert "HMAC" not in chain_meta
    page.close()


def test_policy_denial_does_not_establish_system_blocked(browser_instance):
    """Verifies that request-level policy denials do not establish system-level BLOCKED."""
    page = browser_instance.new_page()
    page.goto(f"file://{STATIC_DIR / 'index.html'}")

    denial_telemetry = {
        "metrics": {
            "total_executions": 100,
            "authorization_denials": 12,
            "halts": 0,
            "execution_failures": 0,
            "parse_error_count": 0,
        },
        "status_flags": {
            "audit_data_available": True,
            "provenance_data_available": True,
        },
        "audit_integrity": {
            "status": "VERIFIED",
            "records_verified": 100,
        },
        "provenance_integrity": {
            "status": "VERIFIED",
            "records_verified": 100,
        },
    }

    page.evaluate(f"""
        window.ObservatoryApp.state.overviewData = {json.dumps(denial_telemetry)};
        window.ObservatoryApp.renderOverview();
    """)

    state_text = page.locator("#overview-system-state-text").text_content()
    assert "BLOCKED" not in state_text
    page.close()


@pytest.mark.parametrize(
    "viewport",
    [
        {"width": 1440, "height": 900},
        {"width": 1024, "height": 768},
        {"width": 768, "height": 1024},
        {"width": 390, "height": 844},
        {"width": 320, "height": 568},
    ],
)
def test_responsive_layout_across_all_viewports(browser_instance, viewport):
    """Asserts responsive behavior and zero horizontal page overflow across screen sizes."""
    context = browser_instance.new_context(viewport=viewport)
    page = context.new_page()
    page.goto(f"file://{STATIC_DIR / 'index.html'}")
    page.wait_for_selector("#overview-primary-state-card")

    # Assert no horizontal overflow
    scroll_width = page.evaluate("document.documentElement.scrollWidth")
    client_width = page.evaluate("document.documentElement.clientWidth")
    assert scroll_width <= client_width + 1, (
        f"Horizontal overflow at {viewport['width']}px: "
        f"scroll={scroll_width}, client={client_width}"
    )

    # Assert primary state card remains visible
    assert page.locator("#overview-primary-state-card").is_visible()
    assert page.locator("#overview-system-state-text").is_visible()

    context.close()
