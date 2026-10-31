"""
Durable automated accessibility regression test suite for EpistemicOS Benchmark Workbench and Control Plane Observatory.

Authoritative regression suite verifying:
1. Automated axe-core scanning across all primary views (Overview, Execution Traces, Provenance Explorer, Benchmark Workbench)
   and dynamic interactive states (trace inspection, lifecycle stage evidence detail, provenance record detail, benchmark case detail,
   empty search filter states).
2. Keyboard navigation through critical workflows (tab navigation, arrow key list traversal, Enter/Space activation,
   search shortcut '/', Escape clear/blur, focus restoration on clear filters).
3. Focus management and keyboard accessibility for scrollable regions (<pre class="inspector-block"> and .table-responsive).
4. Accessible names, ARIA roles, states, and properties across all interactive controls.
5. Table accessibility semantics (scope="col", scope="row") across tabular data displays.
6. Reduced motion compliance (emulating prefers-reduced-motion: reduce and asserting near-zero transition duration).
7. Forced-colors compliance (emulating forced-colors: active and asserting visible solid card boundaries, active tab boundaries, and distinguishable focus outlines).
8. Polite live region announcements (verifying actual, dynamic non-empty text updates on tab switch, record selection, and filter clear).
9. Responsive reflow at 320px width (400% zoom equivalent) verifying zero document-level horizontal page overflow across all 4 views while distinguishing intentional scroll containers.
10. Target size evaluation for interactive elements under WCAG 2.2 2.5.8 across all primary views, implementing normative geometric circle spacing evaluation.
"""

import json
import math
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


AXE_SCRIPT_PATH = Path(__file__).parent / "vendor" / "axe.min.js"


def evaluate_target_size_wcag_258(target, neighbors):
    """
    Evaluate WCAG 2.2 Success Criterion 2.5.8 Target Size (Minimum) (Level AA).

    Normative Rule:
    The size of the target for pointer inputs is at least 24 by 24 CSS pixels, except where:
    - Spacing Exception: Undersized targets (those less than 24 by 24 CSS pixels) are positioned
      such that if a 24 CSS pixel diameter circle is centered on the bounding box of each,
      the circles do not intersect another target or the circle for another target.
      (Equivalently: Euclidean distance between centers of two 24px circles must be >= 24px,
       and target center to edge of any other target must not intersect).

    Args:
        target: dict with {"x": float, "y": float, "width": float, "height": float, "id": str}
        neighbors: list of dicts with same structure for all other interactive targets on the page.

    Returns:
        (bool, str): (passes, reason)
    """
    tw = target.get("width", 0)
    th = target.get("height", 0)

    # 1. Direct pass if >= 24x24 CSS pixels
    if tw >= 24.0 and th >= 24.0:
        return True, "Meets 24x24px minimum"

    # 2. Spacing exception evaluation:
    # A 24px diameter circle centered on the target bounding box (radius R = 12px)
    # Target center: (cx, cy)
    cx = target["x"] + tw / 2.0
    cy = target["y"] + th / 2.0
    radius = 12.0  # 24px diameter / 2

    for n in neighbors:
        if n.get("id") == target.get("id"):
            continue

        nw = n.get("width", 0)
        nh = n.get("height", 0)
        ncx = n["x"] + nw / 2.0
        ncy = n["y"] + nh / 2.0

        # If neighbor is also undersized or evaluated via circles, circle-to-circle collision:
        # Distance between centers must be >= 24px (12px + 12px)
        center_dist = math.sqrt((cx - ncx) ** 2 + (cy - ncy) ** 2)

        # In addition, circle must not intersect the neighbor target bounding box:
        # Closest point on rectangle n to circle center (cx, cy)
        closest_x = max(n["x"], min(cx, n["x"] + nw))
        closest_y = max(n["y"], min(cy, n["y"] + nh))
        dist_to_neighbor_rect = math.sqrt((cx - closest_x) ** 2 + (cy - closest_y) ** 2)

        if dist_to_neighbor_rect < radius:
            return False, f"Circle (radius {radius}px) intersects neighbor '{n.get('id', 'unknown')}' (distance {dist_to_neighbor_rect:.2f}px < {radius}px)"

        if center_dist < 24.0:
            return False, f"24px circle intersects circle of neighbor '{n.get('id', 'unknown')}' (center distance {center_dist:.2f}px < 24px)"

    return True, "Satisfies WCAG 2.5.8 spacing exception (24px non-intersecting circle)"


# ==============================================================================
# Deterministic Unit Tests for WCAG 2.5.8 Geometric Evaluator
# ==============================================================================

def test_unit_target_size_meets_minimum():
    """A target that is at least 24x24 CSS pixels satisfies the criterion directly."""
    target = {"id": "t1", "x": 10, "y": 10, "width": 24, "height": 24}
    passed, reason = evaluate_target_size_wcag_258(target, [])
    assert passed
    assert "Meets 24x24px minimum" in reason


def test_unit_target_size_undersized_satisfies_spacing_exception():
    """An undersized target (e.g. 16x16) separated from neighbors by >= 24px center distance satisfies spacing exception."""
    target = {"id": "t1", "x": 0, "y": 0, "width": 16, "height": 16}  # center at (8, 8)
    # Neighbor center at (40, 8), distance = 32px > 24px; closest edge at x=32, dist to center (8) = 24px >= 12px
    neighbor = {"id": "n1", "x": 32, "y": 0, "width": 16, "height": 16}
    passed, reason = evaluate_target_size_wcag_258(target, [neighbor])
    assert passed
    assert "Satisfies WCAG 2.5.8 spacing exception" in reason


def test_unit_target_size_undersized_fails_too_close():
    """An undersized target fails if neighboring target center is closer than 24px."""
    target = {"id": "t1", "x": 0, "y": 0, "width": 16, "height": 16}  # center (8, 8)
    # Neighbor center at (20, 8), distance = 12px < 24px
    neighbor = {"id": "n1", "x": 12, "y": 0, "width": 16, "height": 16}
    passed, reason = evaluate_target_size_wcag_258(target, [neighbor])
    assert not passed
    assert "intersects" in reason


def test_unit_target_size_overlapping_targets_fail():
    """Overlapping targets fail the spacing exception."""
    target = {"id": "t1", "x": 10, "y": 10, "width": 16, "height": 16}
    neighbor = {"id": "n1", "x": 12, "y": 12, "width": 16, "height": 16}
    passed, reason = evaluate_target_size_wcag_258(target, [neighbor])
    assert not passed


def test_unit_target_size_exact_boundary_threshold():
    """Exact boundary condition: at 24.0px center distance and >= 12px edge distance."""
    target = {"id": "t1", "x": 0, "y": 0, "width": 10, "height": 10}  # center (5, 5)
    # Center at (29, 5), center distance = 24.0px
    # Target center to neighbor edge: neighbor x=24..34, distance from 5 to 24 = 19px >= 12px
    neighbor = {"id": "n1", "x": 24, "y": 0, "width": 10, "height": 10}
    passed, reason = evaluate_target_size_wcag_258(target, [neighbor])
    assert passed

    # Shift neighbor closer by 0.5px -> center distance = 23.5px < 24px -> must fail
    neighbor_close = {"id": "n2", "x": 23.5, "y": 0, "width": 10, "height": 10}
    passed_close, reason_close = evaluate_target_size_wcag_258(target, [neighbor_close])
    assert not passed_close


# ==============================================================================
# Playwright Server Fixture & Browser Integration Tests
# ==============================================================================

@pytest.fixture
def a11y_comprehensive_server(tmp_path):
    audit_file = tmp_path / "epistemic_audit.jsonl"
    provenance_file = tmp_path / "provenance_audit.jsonl"
    ablation_file = tmp_path / "ablation_table.json"
    per_case_file = tmp_path / "per_case_results.json"

    # Multi-entry mock audit log
    audit_events = [
        {
            "event_id": f"aud-00{i}",
            "timestamp": "2026-10-30T12:00:00Z",
            "event_type": "GATE_HALT" if i % 2 == 0 else "GATE_ALLOW",
            "gate_name": "PermissionGate" if i % 2 == 0 else "EntropyGate",
            "reason": "COMMAND_INJECTION_DETECTED" if i % 2 == 0 else "SURPRISAL_WITHIN_BOUNDS",
            "model_id": "epistemic-sentinel-v2",
            "latency_ms": 1.45,
            "payload_hash": "a" * 64,
            "payload_snippet": "rm -rf /critical_db" if i % 2 == 0 else "SELECT 1;",
            "metadata": {"caller": "agent-worker"},
            "prev_hash": "0" * 64 if i == 0 else "b" * 64,
            "entry_hash": f"entry_hash_{i:04d}" + "0" * 49
        }
        for i in range(4)
    ]
    audit_file.write_text("\n".join(json.dumps(ev) for ev in audit_events) + "\n", encoding="utf-8")

    # Multi-entry mock provenance log
    prov_events = [
        {
            "event_id": f"prv-00{i}",
            "correlation_id": f"corr-trace-00{i}",
            "timestamp": f"2026-10-30T12:0{i}:00Z",
            "event_type": "ACTION_PROPOSED" if i == 0 else ("AUTHORIZATION_DENIED" if i == 1 else "EXECUTION_SUCCEEDED"),
            "action_name": "database_query" if i != 1 else "destructive_shell",
            "canonical_target": f"/var/data/table_{i}",
            "payload_digest": "c" * 64,
            "prev_digest": "0" * 64 if i == 0 else "d" * 64,
            "event_digest": f"event_digest_{i:04d}" + "0" * 48,
            "data": {"statement": "SELECT * FROM users"}
        }
        for i in range(4)
    ]
    provenance_file.write_text("\n".join(json.dumps(ev) for ev in prov_events) + "\n", encoding="utf-8")

    # Ablation table artifact
    mock_ablation = {
        "version": "2.1.0",
        "seed": 42,
        "run_id": "run-l4-20261030-a11y-suite",
        "dataset_sha256_digest": "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678",
        "run_records_sha256_digest": "b2c3d4e5f6a17890123456789012345678901234567890123456789012345678",
        "eval_sample_count": 100,
        "baselines": {
            "Ungated Generation": {
                "sample_count": 100,
                "confusion_matrix": {"TC": 35, "FC": 38, "TR": 27, "FR": 0},
                "accuracy_pct": 62.0,
                "accuracy_95ci": [52.21, 70.9],
                "precision_pct": "N/A",
                "recall_pct": 41.54,
                "false_positive_rate_pct": 0.0,
                "false_negative_rate_pct": 58.46,
                "avg_latency_ms": 13.619,
                "total_tokens_spent": 2000
            },
            "Combined Gating": {
                "sample_count": 100,
                "confusion_matrix": {"TC": 35, "FC": 0, "TR": 65, "FR": 0},
                "accuracy_pct": 100.0,
                "accuracy_95ci": [96.38, 100.0],
                "precision_pct": 100.0,
                "recall_pct": 100.0,
                "false_positive_rate_pct": 0.0,
                "false_negative_rate_pct": 0.0,
                "avg_latency_ms": 2.845,
                "total_tokens_spent": 2000
            }
        },
        "paired_mcnemar_comparisons": {
            "Combined Gating vs Ungated Generation": {
                "discordant_a_correct_b_incorrect": 38,
                "discordant_a_incorrect_b_correct": 0,
                "chi2_statistic": 36.0263,
                "p_value": 0.0,
                "statistically_significant_alpha_005": True
            }
        },
        "threshold_ablations": {
            "z_threshold_1.5": {
                "z_threshold": 1.5,
                "TC": 35, "FC": 0, "TR": 65, "FR": 0,
                "precision": 100.0,
                "recall": 100.0
            }
        },
        "attribution": {
            "stopping_benefit": "Entropy gate truncates high-surprisal sequences instantly.",
            "execution_feedback_benefit": "Permission gate eliminates command injections."
        }
    }
    ablation_file.write_text(json.dumps(mock_ablation), encoding="utf-8")

    # Per-case results artifact
    mock_per_case = [
        {
            "run_id": "run-l4-20261030-a11y-suite",
            "dataset_sha256_digest": "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678",
            "baseline": "Combined Gating",
            "case_id": "EVAL-001",
            "scenario_family": "Cyber, Shell & DB Threat Vectors",
            "expected_outcome": "ROLLBACK",
            "actual_outcome": "ROLLBACK",
            "classification": "TR",
            "decision_reason": "PermissionGate: Blocked unauthorized command injection",
            "latency_ms": 1.234,
            "tokens_consumed": 20
        },
        {
            "run_id": "run-l4-20261030-a11y-suite",
            "dataset_sha256_digest": "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678",
            "baseline": "Ungated Generation",
            "case_id": "EVAL-002",
            "scenario_family": "Legitimate Tool Trajectories",
            "expected_outcome": "COMMIT",
            "actual_outcome": "COMMIT",
            "classification": "TC",
            "decision_reason": "Legitimate file read completed without policy violation",
            "latency_ms": 2.115,
            "tokens_consumed": 35
        }
    ]
    per_case_file.write_text(json.dumps(mock_per_case), encoding="utf-8")

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


def run_axe_scan(page, context_label=""):
    """Inject vendor axe.min.js and assert 0 WCAG 2.0 / 2.1 / 2.2 AA violations."""
    assert AXE_SCRIPT_PATH.exists(), f"axe-core vendor script missing at {AXE_SCRIPT_PATH}"
    axe_code = AXE_SCRIPT_PATH.read_text(encoding="utf-8")
    page.evaluate(axe_code)

    results = page.evaluate("""
        () => axe.run({
            runOnly: {
                type: 'tag',
                values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']
            }
        })
    """)

    violations = results.get("violations", [])
    if violations:
        failure_details = []
        for v in violations:
            failure_details.append(f"[{v['id']}] {v['description']} (impact: {v['impact']})")
            for node in v.get("nodes", [])[:3]:
                failure_details.append(f"   Target: {node.get('target')} | Summary: {node.get('failureSummary')}")
        pytest.fail(f"Axe-core WCAG AA violations found in '{context_label}':\n" + "\n".join(failure_details))


@pytest.mark.skipif(not PLAYWRIGHT_AVAILABLE, reason="playwright not installed")
def test_axe_core_scans_across_all_views_and_interactive_states(a11y_comprehensive_server):
    """Run automated axe-core scanning across all 4 tabs and complex interactive states."""
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 900})
        page.goto(f"{a11y_comprehensive_server}/index.html")

        # 1. Overview Tab Scan
        page.click("#tab-overview")
        page.wait_for_selector("#overview-recent-traces")
        run_axe_scan(page, "Overview View")

        # 2. Execution Traces Tab Scan (Initial list)
        page.click("#tab-traces")
        page.wait_for_selector("#trace-list .trace-item")
        run_axe_scan(page, "Execution Traces (List View)")

        # 3. Execution Traces (Selected Trace with Details & Lifecycle Timeline)
        page.click("#trace-list .trace-item")
        page.wait_for_selector("#trace-detail-content:not(.hidden)")
        run_axe_scan(page, "Execution Traces (Selected Trace Detail)")

        # 4. Execution Traces (Evidence Inspector opened via stage selection)
        stages = page.locator(".lifecycle-stage")
        if stages.count() > 0:
            stages.first.click()
            page.wait_for_selector("#area-evidence-inspector")
            run_axe_scan(page, "Execution Traces (Evidence Inspector Opened)")

        # 5. Execution Traces Empty Filter State
        trace_search = page.locator("#trace-search")
        trace_search.fill("nonexistent_filter_query_xyz")
        page.wait_for_timeout(100)
        run_axe_scan(page, "Execution Traces (Empty Filter State)")

        # Clear filter
        trace_clear = page.locator("#area-trace-list button:has-text('Clear Filters')")
        if trace_clear.is_visible():
            trace_clear.click()
            page.wait_for_timeout(100)

        # 6. Provenance Explorer Tab Scan (Initial list)
        page.click("#tab-provenance")
        page.wait_for_selector("#provenance-record-list .trace-item")
        run_axe_scan(page, "Provenance Explorer (Initial List)")

        # 7. Provenance Explorer (Selected Record with Raw JSON Payload)
        page.click("#provenance-record-list .trace-item")
        page.wait_for_selector("#provenance-inspector-content:not(.hidden)")
        run_axe_scan(page, "Provenance Explorer (Record Inspector Detail)")

        # 8. Provenance Explorer Empty Filter State
        prov_search = page.locator("#provenance-search")
        prov_search.fill("nonexistent_filter_query_xyz")
        page.wait_for_timeout(100)
        run_axe_scan(page, "Provenance Explorer (Empty Filter State)")

        # Clear filter
        prov_clear = page.locator("#area-provenance-list button:has-text('Clear Filters')")
        if prov_clear.is_visible():
            prov_clear.click()
            page.wait_for_timeout(100)

        # 9. Benchmark Workbench Tab Scan
        page.click("#tab-benchmarks")
        page.wait_for_selector("#benchmark-run-summary-card")
        run_axe_scan(page, "Benchmark Workbench (Initial View)")

        # 10. Benchmark Workbench (Selected Case Detail Inspector)
        page.click("#benchmark-case-list .trace-item")
        page.wait_for_selector("#benchmark-case-content:not(.hidden)")
        run_axe_scan(page, "Benchmark Workbench (Selected Case Detail)")

        # 11. Benchmark Workbench Empty Filter State
        case_search = page.locator("#benchmark-case-search")
        case_search.fill("nonexistent_case_xyz")
        page.wait_for_timeout(100)
        run_axe_scan(page, "Benchmark Workbench (Empty Case Filter State)")

        browser.close()


@pytest.mark.skipif(not PLAYWRIGHT_AVAILABLE, reason="playwright not installed")
def test_keyboard_navigation_and_focus_management_workflows(a11y_comprehensive_server):
    """Verify keyboard accessibility: arrow key navigation, activation, shortcuts, and focus preservation."""
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 900})
        page.goto(f"{a11y_comprehensive_server}/index.html")

        # 1. Skip Link Operation
        page.keyboard.press("Tab")
        active = page.evaluate("() => document.activeElement.className")
        assert "skip-link" in active

        page.keyboard.press("Enter")
        focused_tag = page.evaluate("() => document.activeElement.id")
        assert focused_tag == "main-content"

        # 2. Global Search Shortcut ('/')
        page.click("#tab-traces")
        page.wait_for_selector("#trace-list .trace-item")
        page.keyboard.press("/")
        assert page.evaluate("() => document.activeElement.id") == "trace-search"

        # 3. Escape key clears search query or blurs
        page.keyboard.type("test query")
        assert page.locator("#trace-search").input_value() == "test query"
        page.keyboard.press("Escape")
        assert page.locator("#trace-search").input_value() == ""

        # 4. Keyboard Arrow Navigation in Traces Listbox
        first_item = page.locator("#trace-list .trace-item").first
        first_item.focus()
        assert page.evaluate("() => document.activeElement.classList.contains('trace-item')")

        page.keyboard.press("ArrowDown")
        second_item_focused = page.evaluate("() => document.activeElement.classList.contains('trace-item')")
        assert second_item_focused

        page.keyboard.press("Enter")
        page.wait_for_selector("#trace-detail-content:not(.hidden)")
        assert page.locator("#trace-detail-content").is_visible()

        # 5. Keyboard Navigation in Provenance Listbox
        page.click("#tab-provenance")
        page.wait_for_selector("#provenance-record-list .trace-item")
        prov_first = page.locator("#provenance-record-list .trace-item").first
        prov_first.focus()
        page.keyboard.press("ArrowDown")
        page.keyboard.press("Enter")
        page.wait_for_selector("#provenance-inspector-content:not(.hidden)")
        assert page.locator("#provenance-inspector-content").is_visible()

        # 6. Keyboard Navigation in Benchmark Cases Listbox
        page.click("#tab-benchmarks")
        page.wait_for_selector("#benchmark-case-list .trace-item")
        case_first = page.locator("#benchmark-case-list .trace-item").first
        case_first.focus()
        page.keyboard.press("ArrowDown")
        page.keyboard.press("Enter")
        page.wait_for_selector("#benchmark-case-content:not(.hidden)")
        assert page.locator("#benchmark-case-content").is_visible()

        # 7. Focusability of Scrollable JSON Region
        raw_pre = page.locator("#benchmark-case-content pre.inspector-block")
        assert raw_pre.is_visible()
        assert raw_pre.get_attribute("tabindex") == "0"
        assert raw_pre.get_attribute("role") == "region"
        assert raw_pre.get_attribute("aria-label") is not None

        raw_pre.focus()
        assert page.evaluate("() => document.activeElement.tagName") == "PRE"

        # 8. Focusability of Scrollable Table Containers in Benchmark Workbench
        table_container = page.locator("#view-benchmarks .table-responsive").first
        assert table_container.get_attribute("tabindex") == "0"
        assert table_container.get_attribute("role") == "region"
        assert table_container.get_attribute("aria-label") is not None

        table_container.focus()
        assert page.evaluate("() => document.activeElement.classList.contains('table-responsive')")

        browser.close()


@pytest.mark.skipif(not PLAYWRIGHT_AVAILABLE, reason="playwright not installed")
def test_table_accessibility_semantics(a11y_comprehensive_server):
    """Verify that all tabular data components define semantic column and row headers."""
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 900})
        page.goto(f"{a11y_comprehensive_server}/index.html")

        # 1. Overview Recent Traces Table
        overview_ths = page.locator("#overview-recent-traces-container table thead th")
        for i in range(overview_ths.count()):
            assert overview_ths.nth(i).get_attribute("scope") == "col"

        # 2. Benchmark Workbench Tables
        page.click("#tab-benchmarks")
        page.wait_for_selector("#benchmark-baselines-tbody")

        baseline_col_ths = page.locator(".table-responsive table thead th")
        for i in range(baseline_col_ths.count()):
            assert baseline_col_ths.nth(i).get_attribute("scope") == "col"

        baseline_row_ths = page.locator("#benchmark-baselines-tbody th[scope='row']")
        assert baseline_row_ths.count() >= 2
        assert "Ungated Generation" in baseline_row_ths.first.text_content()

        mcnemar_row_ths = page.locator("#benchmark-mcnemar-tbody th[scope='row']")
        assert mcnemar_row_ths.count() >= 1

        threshold_row_ths = page.locator("#benchmark-thresholds-tbody th[scope='row']")
        assert threshold_row_ths.count() >= 1

        browser.close()


@pytest.mark.skipif(not PLAYWRIGHT_AVAILABLE, reason="playwright not installed")
def test_live_region_announcements(a11y_comprehensive_server):
    """Verify that the polite live region (#a11y-status-announcer) dynamically updates with non-empty text on actions."""
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 900})
        page.goto(f"{a11y_comprehensive_server}/index.html")

        announcer = page.locator("#a11y-status-announcer")
        assert announcer.count() == 1
        assert announcer.get_attribute("role") == "status"
        assert announcer.get_attribute("aria-live") == "polite"

        # 1. Tab Navigation announcement: clear first, then switch and assert real dynamic update
        page.evaluate("() => { document.getElementById('a11y-status-announcer').textContent = ''; }")
        page.click("#tab-traces")
        page.wait_for_function("() => document.getElementById('a11y-status-announcer').textContent.length > 0")
        assert "Execution Trace Explorer" in announcer.text_content()

        # 2. Trace selection announcement: clear first, click trace, assert update
        page.wait_for_selector("#trace-list .trace-item")
        page.evaluate("() => { document.getElementById('a11y-status-announcer').textContent = ''; }")
        page.click("#trace-list .trace-item")
        page.wait_for_function("() => document.getElementById('a11y-status-announcer').textContent.length > 0")
        assert "Selected execution trace" in announcer.text_content()

        # 3. Filter clearing announcement: clear announcer, fill filter, click clear, assert announcement
        trace_search = page.locator("#trace-search")
        trace_search.fill("no_such_trace_abc")
        page.wait_for_timeout(100)
        clear_btn = page.locator("#area-trace-list button:has-text('Clear Filters')")
        if clear_btn.is_visible():
            page.evaluate("() => { document.getElementById('a11y-status-announcer').textContent = ''; }")
            clear_btn.click()
            page.wait_for_function("() => document.getElementById('a11y-status-announcer').textContent.length > 0")
            assert "Trace filters cleared" in announcer.text_content()

        # 4. Provenance Navigation and Selection
        page.evaluate("() => { document.getElementById('a11y-status-announcer').textContent = ''; }")
        page.click("#tab-provenance")
        page.wait_for_function("() => document.getElementById('a11y-status-announcer').textContent.length > 0")
        assert "Provenance Explorer" in announcer.text_content()

        page.wait_for_selector("#provenance-record-list .trace-item")
        page.evaluate("() => { document.getElementById('a11y-status-announcer').textContent = ''; }")
        page.click("#provenance-record-list .trace-item")
        page.wait_for_function("() => document.getElementById('a11y-status-announcer').textContent.length > 0")
        assert "Selected provenance record" in announcer.text_content()

        # 5. Benchmark Navigation and Selection
        page.evaluate("() => { document.getElementById('a11y-status-announcer').textContent = ''; }")
        page.click("#tab-benchmarks")
        page.wait_for_function("() => document.getElementById('a11y-status-announcer').textContent.length > 0")
        assert "Benchmark Workbench" in announcer.text_content()

        page.wait_for_selector("#benchmark-case-list .trace-item")
        page.evaluate("() => { document.getElementById('a11y-status-announcer').textContent = ''; }")
        page.click("#benchmark-case-list .trace-item")
        page.wait_for_function("() => document.getElementById('a11y-status-announcer').textContent.length > 0")
        assert "Selected benchmark case" in announcer.text_content()

        browser.close()


@pytest.mark.skipif(not PLAYWRIGHT_AVAILABLE, reason="playwright not installed")
def test_prefers_reduced_motion_behavior(a11y_comprehensive_server):
    """Verify that CSS animations and transitions respect prefers-reduced-motion: reduce."""
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(
            viewport={"width": 1440, "height": 900},
            reduced_motion="reduce"
        )
        page.goto(f"{a11y_comprehensive_server}/index.html")

        # Verify that transitions have near-zero duration or animations are disabled
        tab_duration = page.evaluate("""
            () => {
                const el = document.querySelector('.nav-tab');
                return window.getComputedStyle(el).transitionDuration;
            }
        """)
        # In style.css under @media (prefers-reduced-motion: reduce): transition-duration: 0.01ms !important;
        assert "0.01ms" in tab_duration or "0s" in tab_duration or float(tab_duration.replace("s", "")) < 0.001

        browser.close()


@pytest.mark.skipif(not PLAYWRIGHT_AVAILABLE, reason="playwright not installed")
def test_forced_colors_support(a11y_comprehensive_server):
    """Verify that under forced-colors: active, containers render distinguishable solid boundaries, focus outlines, and distinct states."""
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(
            viewport={"width": 1440, "height": 900},
            forced_colors="active"
        )
        page.goto(f"{a11y_comprehensive_server}/index.html")

        # 1. Verify card boundaries render explicit solid border styles with non-zero width
        card_styles = page.evaluate("""
            () => {
                const card = document.querySelector('.card');
                const cs = window.getComputedStyle(card);
                return {
                    borderStyle: cs.borderStyle,
                    borderWidth: parseFloat(cs.borderTopWidth || '0'),
                    borderColor: cs.borderTopColor
                };
            }
        """)
        assert card_styles["borderStyle"] == "solid", f"Card borderStyle expected 'solid' under forced-colors, got '{card_styles['borderStyle']}'"
        assert card_styles["borderWidth"] > 0, "Card borderWidth expected > 0 under forced-colors"
        assert card_styles["borderColor"] not in ["transparent", "rgba(0, 0, 0, 0)"], "Card borderColor must not be transparent"

        # 2. Verify active vs inactive navigation tabs have distinguishable state affordances
        tab_states = page.evaluate("""
            () => {
                const activeTab = document.querySelector('.nav-tab.active');
                const inactiveTabs = Array.from(document.querySelectorAll('.nav-tab:not(.active)'));
                const csActive = window.getComputedStyle(activeTab);
                const csInactive = window.getComputedStyle(inactiveTabs[0]);
                return {
                    activeSelected: activeTab.getAttribute('aria-selected'),
                    activeBorder: csActive.borderBottomWidth,
                    inactiveBorder: csInactive.borderBottomWidth,
                    activeBg: csActive.backgroundColor,
                    inactiveBg: csInactive.backgroundColor
                };
            }
        """)
        assert tab_states["activeSelected"] == "true"
        # Verify active and inactive tabs have distinguishable border or background
        has_distinction = (tab_states["activeBorder"] != tab_states["inactiveBorder"]) or (tab_states["activeBg"] != tab_states["inactiveBg"])
        assert has_distinction, "Active and inactive tabs must have distinguishable computed visual affordances under forced-colors"

        # 3. Verify focus outlines remain distinguishable when keyboard focus moves via Tab key
        page.keyboard.press("Tab") # focuses skip-link
        page.keyboard.press("Tab") # focuses tab-overview button
        outline_styles = page.evaluate("""
            () => {
                const focused = document.activeElement;
                const cs = window.getComputedStyle(focused);
                return {
                    tag: focused.tagName,
                    id: focused.id,
                    outlineStyle: cs.outlineStyle,
                    outlineWidth: parseFloat(cs.outlineWidth || '0'),
                    outlineColor: cs.outlineColor
                };
            }
        """)
        assert outline_styles["outlineStyle"] == "solid", f"Focus outlineStyle expected 'solid', got '{outline_styles['outlineStyle']}'"
        assert outline_styles["outlineWidth"] > 0, f"Focus outlineWidth must be > 0, got {outline_styles['outlineWidth']}"
        assert outline_styles["outlineColor"] not in ["transparent", "rgba(0, 0, 0, 0)"], "Focus outlineColor must be visible"

        # 4. Text readable against computed background
        text_colors = page.evaluate("""
            () => {
                const title = document.querySelector('h1, h2');
                const cs = window.getComputedStyle(title);
                return {
                    color: cs.color,
                    bg: cs.backgroundColor
                };
            }
        """)
        assert text_colors["color"] != text_colors["bg"], "Text color must not match background color under forced-colors"

        # 5. Negative control: verify our test detects suppressed outlines
        negative_control = page.evaluate("""
            () => {
                const dummy = document.createElement('button');
                dummy.style.outline = 'none';
                document.body.appendChild(dummy);
                const cs = window.getComputedStyle(dummy);
                const isSuppressed = cs.outlineStyle === 'none' || parseFloat(cs.outlineWidth || '0') === 0;
                dummy.remove();
                return isSuppressed;
            }
        """)
        assert negative_control, "Test harness must detect suppressed outline under negative control"

        browser.close()


@pytest.mark.skipif(not PLAYWRIGHT_AVAILABLE, reason="playwright not installed")
def test_responsive_reflow_narrow_viewport_320px(a11y_comprehensive_server):
    """Verify WCAG 1.4.10 Reflow across all 4 primary views at 320px width without page-level overflow or clipped controls."""
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 320, "height": 640})
        page.goto(f"{a11y_comprehensive_server}/index.html")

        def assert_view_reflow(view_id, view_name):
            # Assert document-level horizontal overflow is zero
            scroll_width = page.evaluate("() => document.documentElement.scrollWidth")
            inner_width = page.evaluate("() => window.innerWidth")
            assert scroll_width <= inner_width, f"Document overflow detected in {view_name}: scrollWidth ({scroll_width}) > innerWidth ({inner_width})"

            # Assert view panel container is visible and bounded
            view_panel = page.locator(f"#{view_id}")
            assert view_panel.is_visible()
            panel_box = view_panel.bounding_box()
            assert panel_box["width"] <= 320, f"{view_name} panel width ({panel_box['width']}) exceeds viewport (320)"

        # 1. Overview View Reflow
        assert_view_reflow("view-overview", "Overview")
        refresh_box = page.locator("#btn-refresh-overview").bounding_box()
        assert refresh_box and refresh_box["x"] >= 0 and (refresh_box["x"] + refresh_box["width"]) <= 320

        # 2. Execution Traces View Reflow
        page.click("#tab-traces")
        page.wait_for_timeout(100)
        assert_view_reflow("view-traces", "Execution Traces")
        search_box = page.locator("#trace-search").bounding_box()
        assert search_box and search_box["x"] >= 0 and (search_box["x"] + search_box["width"]) <= 320

        # 3. Provenance Explorer View Reflow
        page.click("#tab-provenance")
        page.wait_for_timeout(100)
        assert_view_reflow("view-provenance", "Provenance Explorer")
        prov_search_box = page.locator("#provenance-search").bounding_box()
        assert prov_search_box and prov_search_box["x"] >= 0 and (prov_search_box["x"] + prov_search_box["width"]) <= 320

        # 4. Benchmark Workbench View Reflow
        page.click("#tab-benchmarks")
        page.wait_for_timeout(100)
        assert_view_reflow("view-benchmarks", "Benchmark Workbench")
        # In Benchmark Workbench, verify that table-responsive container allows intentional internal horizontal scrolling
        table_container = page.locator("#view-benchmarks .table-responsive").first
        assert table_container.is_visible()
        table_box = table_container.bounding_box()
        assert table_box["width"] <= 320

        # The internal table inside .table-responsive can have scrollWidth >= clientWidth (intentional internal scroll)
        internal_scroll = page.evaluate("""
            () => {
                const el = document.querySelector('#view-benchmarks .table-responsive');
                return el.scrollWidth >= el.clientWidth;
            }
        """)
        assert internal_scroll, "Internal table container should contain wide data without forcing page overflow"

        browser.close()


@pytest.mark.skipif(not PLAYWRIGHT_AVAILABLE, reason="playwright not installed")
def test_target_size_wcag_258(a11y_comprehensive_server):
    """
    Evaluate interactive targets against WCAG 2.2 2.5.8 minimum target size (>= 24x24 CSS pixels).
    Applies normative 24px diameter circle spacing exception without class-based exemptions.
    """
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 900})
        page.goto(f"{a11y_comprehensive_server}/index.html")

        views = [
            ("#tab-overview", "#view-overview"),
            ("#tab-traces", "#view-traces"),
            ("#tab-provenance", "#view-provenance"),
            ("#tab-benchmarks", "#view-benchmarks")
        ]

        failures = []

        for tab_selector, view_selector in views:
            page.click(tab_selector)
            page.wait_for_timeout(100)

            # Query all interactive targets in current view and shell navigation
            interactive_data = page.evaluate("""
                (selector) => {
                    const selectorStr = selector + ' button, ' + selector + ' select, ' + selector + ' input[type="search"], ' + selector + ' li.trace-item, .nav-tab';
                    const elements = Array.from(document.querySelectorAll(selectorStr));
                    return elements.map((el, idx) => {
                        const rect = el.getBoundingClientRect();
                        const tag = el.tagName.toLowerCase();
                        const text = (el.textContent || el.getAttribute('aria-label') || '').trim().replace(/\\s+/g, ' ').substring(0, 30);
                        const id = el.id ? '#' + el.id : (el.className ? '.' + el.className.split(' ')[0] : tag + '_' + idx);
                        return {
                            id: id + '_' + idx,
                            tag: tag,
                            text: text,
                            x: rect.x,
                            y: rect.y,
                            width: rect.width,
                            height: rect.height,
                            visible: rect.width > 0 && rect.height > 0 && window.getComputedStyle(el).visibility !== 'hidden'
                        };
                    }).filter(e => e.visible);
                }
            """, view_selector)

            for target in interactive_data:
                # Geometric circle evaluation without class-based exemptions
                passed, reason = evaluate_target_size_wcag_258(target, interactive_data)
                if not passed:
                    failures.append(f"View {view_selector} [{target['tag']}] '{target['text']}' ({target['width']:.1f}x{target['height']:.1f}px): {reason}")

        if failures:
            pytest.fail(f"WCAG 2.5.8 target size failures detected:\n" + "\n".join(failures))

        browser.close()
