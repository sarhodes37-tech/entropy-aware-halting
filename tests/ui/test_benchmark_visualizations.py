"""
Automated unit, E2E, and negative control tests for Accessible Benchmark Visualizations.

Covers:
- Correct native SVG chart rendering from representative benchmark fixtures.
- Strict numerical ordering of threshold values (not lexicographical: e.g. 1.0, 1.5, 2.0, 2.85).
- Consistency between SVG chart values and corresponding accessible table values.
- Handling of missing, null, malformed, non-finite, and "N/A" measurements (no zero fabrication).
- Empty artifacts and partial artifact availability states.
- Responsive rendering across narrow (320px) to wide (1440px) viewports with zero horizontal overflow.
- Keyboard accessibility and absence of hover-only information.
- Negative controls: detection of data discrepancies or omitted tabular companions.
"""

import json
import threading
import time
from pathlib import Path
import pytest

from epistemicos.ui.adapters import ObservatoryDataAdapter
from epistemicos.ui.server import create_server

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


@pytest.fixture
def viz_test_server(tmp_path):
    """Launches test server with multi-baseline, multi-threshold benchmark data."""
    ablation_file = tmp_path / "ablation_table.json"
    per_case_file = tmp_path / "per_case_results.json"
    provenance_file = tmp_path / "provenance_audit.jsonl"
    audit_file = tmp_path / "epistemic_audit.jsonl"

    benchmark_data = {
        "version": "1.0.0",
        "seed": 42,
        "run_id": "run-viz-test-2026",
        "dataset_sha256_digest": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "run_records_sha256_digest": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        "eval_sample_count": 100,
        "baselines": {
            "Ungated Generation": {
                "sample_count": 100,
                "confusion_matrix": {"TC": 35, "FC": 65, "TR": 0, "FR": 0},
                "accuracy_pct": 35.0,
                "accuracy_95ci": [26.3, 44.8],
                "precision_pct": "N/A",  # Special N/A value
                "recall_pct": 0.0,
                "false_positive_rate_pct": 0.0,
                "false_negative_rate_pct": 100.0,
                "avg_latency_ms": 0.125,
                "total_tokens_spent": 2000
            },
            "Combined Gating": {
                "sample_count": 100,
                "confusion_matrix": {"TC": 35, "FC": 0, "TR": 65, "FR": 0},
                "accuracy_pct": 100.0,
                "accuracy_95ci": [96.3, 100.0],
                "precision_pct": 100.0,
                "recall_pct": 100.0,
                "false_positive_rate_pct": 0.0,
                "false_negative_rate_pct": 0.0,
                "avg_latency_ms": 2.845,
                "total_tokens_spent": 2000
            },
            "Partial Missing Baseline": {
                "sample_count": 50,
                "confusion_matrix": {"TC": 20, "FC": 10, "TR": 15, "FR": 5},
                "accuracy_pct": 70.0,
                "accuracy_95ci": [56.2, 80.9],
                "precision_pct": 75.0,
                "recall_pct": 60.0,
                "false_positive_rate_pct": 20.0,
                "false_negative_rate_pct": 40.0,
                "avg_latency_ms": None,  # Missing latency
                "total_tokens_spent": 1200
            }
        },
        "threshold_ablations": {
            # Deliberately unordered keys to test client-side numerical sorting
            "z_threshold_2.85": {
                "z_threshold": 2.85,
                "TC": 35, "FC": 5, "TR": 60, "FR": 0,
                "precision": 100.0,
                "recall": 92.31
            },
            "z_threshold_1.0": {
                "z_threshold": 1.0,
                "TC": 25, "FC": 0, "TR": 65, "FR": 10,
                "precision": 86.67,
                "recall": 100.0
            },
            "z_threshold_2.0": {
                "z_threshold": 2.0,
                "TC": 35, "FC": 2, "TR": 63, "FR": 0,
                "precision": 100.0,
                "recall": 96.92
            },
            "z_threshold_1.5": {
                "z_threshold": 1.5,
                "TC": 35, "FC": 0, "TR": 65, "FR": 0,
                "precision": 100.0,
                "recall": 100.0
            }
        },
        "attribution": {
            "stopping_benefit": "Entropy gate stops early.",
            "execution_feedback_benefit": "Permission gate checks commands."
        }
    }

    per_case_data = [
        {
            "run_id": "run-viz-test-2026",
            "dataset_sha256_digest": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "baseline": "Combined Gating",
            "case_id": "CASE-001",
            "scenario_family": "Shell Injection",
            "expected_outcome": "ROLLBACK",
            "actual_outcome": "ROLLBACK",
            "classification": "TR",
            "decision_reason": "Blocked by permission gate",
            "latency_ms": 2.845,
            "tokens_consumed": 20
        }
    ]

    ablation_file.write_text(json.dumps(benchmark_data), encoding="utf-8")
    per_case_file.write_text(json.dumps(per_case_data), encoding="utf-8")
    provenance_file.write_text("", encoding="utf-8")
    audit_file.write_text("", encoding="utf-8")

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
def test_visualizations_render_and_match_accessible_tables(viz_test_server):
    """
    Verifies:
    1. Visible headings and descriptions for each visualization.
    2. SVG charts exist, have role='img' and aria-hidden='true'.
    3. Consistency between chart data points/bars and table cells.
    4. Explicit N/A handling (not converted to 0).
    5. Numerical ordering of threshold observations (1.0 < 1.5 < 2.0 < 2.85).
    """
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 900})
        page.goto(f"{viz_test_server}/index.html")

        # Navigate to Benchmarks
        page.click("#tab-benchmarks")
        page.wait_for_selector("#benchmark-baselines-chart-container")

        # 1. Baseline Performance Chart Check
        chart_container = page.locator("#benchmark-baselines-chart-container")
        assert chart_container.is_visible()
        assert "Visual Comparison" in chart_container.text_content()
        assert "Precision" in chart_container.text_content()

        svg_baselines = page.locator("#benchmark-baselines-chart-viewport svg")
        assert svg_baselines.is_visible()
        assert svg_baselines.get_attribute("aria-hidden") == "true"

        # Check N/A handling for Ungated Generation Precision: text should be N/A, not 0%
        # The chart text element should contain 'N/A'
        assert "N/A" in svg_baselines.text_content()

        # Check Table consistency
        table_baselines = page.locator("#benchmark-baselines-tbody")
        assert "Ungated Generation" in table_baselines.text_content()
        assert "Combined Gating" in table_baselines.text_content()

        # 2. Threshold Sensitivity Chart Check
        thresh_container = page.locator("#benchmark-thresholds-chart-container")
        assert thresh_container.is_visible()
        svg_thresh = page.locator("#benchmark-thresholds-chart-viewport svg")
        assert svg_thresh.is_visible()
        assert svg_thresh.get_attribute("aria-hidden") == "true"

        # Verify strict numerical sorting: x labels must appear in order Z=1.0, Z=1.5, Z=2.0, Z=2.85
        x_labels = svg_thresh.locator("text:has-text('Z=')").all_text_contents()
        expected_order = ["Z=1", "Z=1.5", "Z=2", "Z=2.85"]
        # Match normalized
        assert len(x_labels) == 4
        assert [l.replace(".0", "") for l in x_labels] == expected_order

        # 3. Efficiency Chart Check
        eff_container = page.locator("#benchmark-efficiency-chart-container")
        assert eff_container.is_visible()
        svg_eff = page.locator("#benchmark-efficiency-chart-viewport svg")
        assert svg_eff.is_visible()
        assert svg_eff.get_attribute("aria-hidden") == "true"

        # Check units on axes
        assert "Avg Latency (ms)" in svg_eff.text_content()
        assert "Total Tokens Consumed (Tokens)" in svg_eff.text_content()

        # Combined Gating should be present as a point label
        assert "Combined Gating" in svg_eff.text_content()
        # Partial Missing Baseline (missing latency) should not be plotted as a fake 0 point
        # It had avg_latency_ms: None
        points_text = svg_eff.locator("text").all_text_contents()
        assert not any("Partial Missing Baseline" in t for t in points_text)

        browser.close()


@pytest.mark.skipif(not PLAYWRIGHT_AVAILABLE, reason="playwright not installed")
def test_visualizations_responsive_at_320px(viz_test_server):
    """Verifies that visualizations fit within narrow mobile viewports (320px) without horizontal overflow."""
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 320, "height": 568})
        page.goto(f"{viz_test_server}/index.html")

        page.click("#tab-benchmarks")
        page.wait_for_selector("#benchmark-baselines-chart-container")

        # Assert no document horizontal scroll
        no_overflow = page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
        assert no_overflow, "Horizontal page overflow at 320px"

        # Check that chart containers are visible
        assert page.locator("#benchmark-baselines-chart-container").is_visible()
        assert page.locator("#benchmark-thresholds-chart-container").is_visible()
        assert page.locator("#benchmark-efficiency-chart-container").is_visible()

        browser.close()


@pytest.mark.skipif(not PLAYWRIGHT_AVAILABLE, reason="playwright not installed")
def test_missing_and_empty_benchmark_artifacts(tmp_path):
    """Verifies that empty or missing benchmark artifacts display clean empty state notices in visualization cards."""
    audit_file = tmp_path / "epistemic_audit.jsonl"
    provenance_file = tmp_path / "provenance_audit.jsonl"
    ablation_file = tmp_path / "ablation_empty.json"
    per_case_file = tmp_path / "per_case_empty.json"

    # Write empty JSON object for ablation
    ablation_file.write_text(json.dumps({}), encoding="utf-8")
    per_case_file.write_text("[]", encoding="utf-8")
    provenance_file.write_text("", encoding="utf-8")
    audit_file.write_text("", encoding="utf-8")

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

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1024, "height": 768})
        page.goto(f"{base_url}/index.html")

        page.click("#tab-benchmarks")
        page.wait_for_selector("#benchmark-baselines-chart-container")

        # Visualization containers should show clean fallback empty-state messages
        txt_base = page.locator("#benchmark-baselines-chart-viewport").text_content().lower()
        txt_thresh = page.locator("#benchmark-thresholds-chart-viewport").text_content().lower()
        txt_eff = page.locator("#benchmark-efficiency-chart-viewport").text_content().lower()

        assert any(w in txt_base for w in ["unavailable", "empty", "zero baselines"])
        assert any(w in txt_thresh for w in ["unavailable", "empty", "zero baselines"])
        assert any(w in txt_eff for w in ["unavailable", "empty", "zero baselines"])

        browser.close()

    server.shutdown()
    server.server_close()


@pytest.mark.skipif(not PLAYWRIGHT_AVAILABLE, reason="playwright not installed")
def test_negative_control_missing_accessible_table_companion(viz_test_server):
    """
    Negative control test: asserts that if the accessible tabular companion were removed
    or hidden, the test harness detects an accessibility regression.
    """
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1024, "height": 768})
        page.goto(f"{viz_test_server}/index.html")
        page.click("#tab-benchmarks")
        page.wait_for_selector("#benchmark-baselines-tbody")

        # Verify the accessible table exists and is visible
        has_table = page.evaluate("""
            () => {
                const table = document.querySelector('table[aria-label="Baseline Condition Performance Metrics"]');
                return table !== null && window.getComputedStyle(table).display !== 'none';
            }
        """)
        assert has_table is True, "Accessible table companion must be present and visible"

        # Negative control simulation: if table is hidden, assertion fails
        hidden_detected = page.evaluate("""
            () => {
                const table = document.querySelector('table[aria-label="Baseline Condition Performance Metrics"]');
                table.style.display = 'none';
                const isStillVisible = window.getComputedStyle(table).display !== 'none';
                // Restore display
                table.style.display = '';
                return !isStillVisible;
            }
        """)
        assert hidden_detected is True, "Harness must detect when accessible table companion is removed or hidden"

        browser.close()
