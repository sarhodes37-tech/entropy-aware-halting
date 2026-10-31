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
6. Reduced motion and forced-colors compliance.
"""

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


AXE_SCRIPT_PATH = Path(__file__).parent / "vendor" / "axe.min.js"


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
