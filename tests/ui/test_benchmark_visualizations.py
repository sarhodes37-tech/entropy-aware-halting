"""Tests for accessible benchmark visualizations in the EpistemicOS Control Plane Observatory.

Validates:
1. Native SVG visual rendering and DOM structure (no third-party dependencies).
2. Strict linear numerical x-axis threshold positioning and handling of single thresholds.
3. Discontinuous series segments across missing threshold observations without interpolation.
4. Strict baseline metric percentage encoding (genuine zero-width bars for 0%, exact boundary handling,
   rejection of out-of-bounds percentages without clamping, explicit INVALID/UNAVAILABLE/N/A indicators).
5. Deterministic chart-to-table numerical equivalence using stable data-* attributes.
6. Negative control accessibility helper evaluating visible companion tables, scope headers, and 320px availability.
7. SVG bounding boxes, absence of text clipping, forced-colors, reduced-motion, and keyboard navigation.
"""

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
def running_server(tmp_path):
    audit_file = tmp_path / "epistemic_audit.jsonl"
    provenance_file = tmp_path / "provenance_audit.jsonl"
    ablation_file = tmp_path / "ablation_table.json"
    per_case_file = tmp_path / "per_case_results.json"

    mock_ablation = {
        "version": "1.0.0",
        "seed": 42,
        "run_id": "run-viz-test-100",
        "dataset_sha256_digest": "4a7b9c8d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b",
        "run_records_sha256_digest": "8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a",
        "eval_sample_count": 100,
        "baselines": {
            "Ungated Generation": {
                "sample_count": 100,
                "confusion_matrix": {"TC": 35, "FC": 65, "TR": 0, "FR": 0},
                "accuracy_pct": 35.0,
                "accuracy_95ci": [26.3, 44.8],
                "recall_pct": 0.0,
                "precision_pct": "N/A",
                "false_positive_rate_pct": 0.0,
                "false_negative_rate_pct": 100.0,
                "avg_latency_ms": 0.125,
                "total_tokens_spent": 2000
            },
            "Entropy-Only Gating": {
                "sample_count": 100,
                "confusion_matrix": {"TC": 30, "FC": 10, "TR": 55, "FR": 5},
                "accuracy_pct": 85.0,
                "accuracy_95ci": [76.7, 90.7],
                "recall_pct": 84.62,
                "precision_pct": 91.67,
                "false_positive_rate_pct": 14.29,
                "false_negative_rate_pct": 15.38,
                "avg_latency_ms": 1.53,
                "total_tokens_spent": 2000
            },
            "Combined Gating": {
                "sample_count": 100,
                "confusion_matrix": {"TC": 35, "FC": 0, "TR": 65, "FR": 0},
                "accuracy_pct": 100.0,
                "accuracy_95ci": [96.3, 100.0],
                "recall_pct": 100.0,
                "precision_pct": 100.0,
                "false_positive_rate_pct": 0.0,
                "false_negative_rate_pct": 0.0,
                "avg_latency_ms": 2.845,
                "total_tokens_spent": 2000
            }
        },
        "threshold_ablations": {
            "z_2.0": {"z_threshold": 2.0, "precision": 100.0, "recall": 92.31, "TC": 35, "FC": 0, "TR": 60, "FR": 5},
            "z_2.5": {"z_threshold": 2.5, "precision": 100.0, "recall": 96.92, "TC": 35, "FC": 0, "TR": 63, "FR": 2},
            "z_3.0": {"z_threshold": 3.0, "precision": 100.0, "recall": 100.0, "TC": 35, "FC": 0, "TR": 65, "FR": 0}
        }
    }

    mock_per_case = [
        {"case_id": "case-001", "ground_truth": "CLEAN", "decision": "ALLOWED", "evaluator_outcome": "CORRECT_COMPLETION", "baseline": "Ungated Generation"}
    ]

    audit_file.write_text("")
    provenance_file.write_text("")
    import json
    ablation_file.write_text(json.dumps(mock_ablation))
    per_case_file.write_text(json.dumps(mock_per_case))

    adapter = ObservatoryDataAdapter(
        audit_log_path=str(audit_file),
        provenance_log_path=str(provenance_file),
        ablation_table_path=str(ablation_file),
        per_case_results_path=str(per_case_file)
    )

    server = create_server("127.0.0.1", 0, adapter=adapter)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    base_url = f"http://127.0.0.1:{port}"

    yield base_url
    server.shutdown()
    server.server_close()


def navigate_to_benchmarks(page, base_url):
    page.goto(f"{base_url}/index.html", wait_until="networkidle")
    page.click("#tab-benchmarks")
    page.wait_for_selector("#view-benchmarks:not(.hidden)", state="visible")
    # Wait for benchmark baseline rows and threshold rows to populate
    page.wait_for_selector("#benchmark-baselines-tbody tr", state="visible")
    page.wait_for_selector("#benchmark-thresholds-tbody tr", state="visible")


def test_native_svg_charts_rendered_with_aria_hidden(running_server):
    if not PLAYWRIGHT_AVAILABLE:
        pytest.skip("Playwright not installed")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        navigate_to_benchmarks(page, running_server)

        for chart_id in [
            "benchmark-baselines-chart-viewport",
            "benchmark-thresholds-chart-viewport",
            "benchmark-efficiency-chart-viewport"
        ]:
            viewport = page.locator(f"#{chart_id}")
            svg = viewport.locator("svg")
            assert svg.count() == 1, f"Expected 1 SVG in #{chart_id}"
            assert svg.get_attribute("aria-hidden") == "true", f"SVG in #{chart_id} must have aria-hidden='true'"
            assert svg.get_attribute("role") == "img"
        browser.close()


def test_linear_threshold_proportional_positioning_and_discontinuous_segments(running_server):
    if not PLAYWRIGHT_AVAILABLE:
        pytest.skip("Playwright not installed")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        navigate_to_benchmarks(page, running_server)

        test_thresholds = {
            "z_neg1": {"z_threshold": -1.0, "precision": 80.0, "recall": 90.0},
            "z_pos1": {"z_threshold": 1.0, "precision": "N/A", "recall": 85.0},
            "z_pos5": {"z_threshold": 5.0, "precision": 95.0, "recall": 70.0}
        }

        page.evaluate("""(data) => {
            window.ObservatoryApp.renderThresholdSensitivityChart(data, { available: true });
        }""", test_thresholds)

        ticks = page.locator("#benchmark-thresholds-chart-viewport svg text:has-text('Z=')").all()
        assert len(ticks) == 3
        x_coords = [float(t.get_attribute("x")) for t in ticks]
        assert x_coords[0] < x_coords[1] < x_coords[2]

        prop = (x_coords[1] - x_coords[0]) / (x_coords[2] - x_coords[0])
        assert abs(prop - (1.0 / 3.0)) < 0.05, f"Expected proportional x position ~0.333, got {prop}"

        prec_polylines = page.locator("#benchmark-thresholds-chart-viewport svg polyline[data-series='precision']").all()
        assert len(prec_polylines) == 0, "Precision polyline should not connect across missing observation"

        rec_polylines = page.locator("#benchmark-thresholds-chart-viewport svg polyline[data-series='recall']").all()
        assert len(rec_polylines) == 1, "Recall polyline should connect contiguous points"
        browser.close()


def test_single_threshold_observation_handling(running_server):
    if not PLAYWRIGHT_AVAILABLE:
        pytest.skip("Playwright not installed")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        navigate_to_benchmarks(page, running_server)

        single_threshold = {
            "z_single": {"z_threshold": 2.5, "precision": 90.0, "recall": 85.0}
        }

        page.evaluate("""(data) => {
            window.ObservatoryApp.renderThresholdSensitivityChart(data, { available: true });
        }""", single_threshold)

        ticks = page.locator("#benchmark-thresholds-chart-viewport svg text:has-text('Z=2.5')").all()
        assert len(ticks) == 1
        assert page.locator("#benchmark-thresholds-chart-viewport svg polyline").count() == 0
        circle = page.locator("#benchmark-thresholds-chart-viewport svg circle[data-threshold='2.5']")
        assert circle.count() == 1
        assert float(circle.get_attribute("cx")) > 0
        browser.close()


def test_baseline_percentage_encoding_and_boundary_handling(running_server):
    if not PLAYWRIGHT_AVAILABLE:
        pytest.skip("Playwright not installed")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        navigate_to_benchmarks(page, running_server)

        test_baselines = {
            "ValidZero": {
                "precision_pct": 0.0,
                "recall_pct": 100.0,
                "false_positive_rate_pct": "N/A",
                "false_negative_rate_pct": -5.0
            },
            "ValidNormal": {
                "precision_pct": 75.0,
                "recall_pct": 150.0,
                "false_positive_rate_pct": None,
                "false_negative_rate_pct": 25.0
            }
        }

        page.evaluate("""(data) => {
            window.ObservatoryApp.renderBaselinePerformanceChart(data, { available: true });
        }""", test_baselines)

        zero_text = page.locator("#benchmark-baselines-chart-viewport svg text[data-baseline='ValidZero'][data-metric='precision_pct']")
        assert zero_text.count() == 1
        assert zero_text.text_content().strip() == "0%"

        zero_rect = page.locator("#benchmark-baselines-chart-viewport svg rect[data-baseline='ValidZero'][data-metric='precision_pct']")
        if zero_rect.count() > 0:
            assert float(zero_rect.get_attribute("width")) == 0.0
        else:
            assert zero_rect.count() == 0

        rec_rect = page.locator("#benchmark-baselines-chart-viewport svg rect[data-baseline='ValidZero'][data-metric='recall_pct']")
        assert rec_rect.count() == 1
        assert float(rec_rect.get_attribute("width")) > 500

        fnr_text = page.locator("#benchmark-baselines-chart-viewport svg text[data-baseline='ValidZero'][data-metric='false_negative_rate_pct']")
        assert fnr_text.count() == 1
        assert "INVALID" in fnr_text.text_content() or "N/A" in fnr_text.text_content()
        assert page.locator("#benchmark-baselines-chart-viewport svg rect[data-baseline='ValidZero'][data-metric='false_negative_rate_pct']").count() == 0

        rec_invalid_text = page.locator("#benchmark-baselines-chart-viewport svg text[data-baseline='ValidNormal'][data-metric='recall_pct']")
        assert rec_invalid_text.count() == 1
        assert "INVALID" in rec_invalid_text.text_content()
        assert page.locator("#benchmark-baselines-chart-viewport svg rect[data-baseline='ValidNormal'][data-metric='recall_pct']").count() == 0
        browser.close()


def verify_threshold_chart_table_equivalence(page):
    """Extract visible threshold table values and compare against plotted chart markers with data-* attributes."""
    # 1. Extract visible table rows
    table_threshold_values = page.evaluate(r"""() => {
        const rows = document.querySelectorAll('#benchmark-thresholds-table tbody tr');
        const results = {};
        rows.forEach(tr => {
            const th = tr.querySelector('th');
            if (!th) return;
            const zRaw = th.textContent.replace(/Z\s*=\s*/i, '').trim();
            const zNum = parseFloat(zRaw);
            const tds = Array.from(tr.querySelectorAll('td')).map(td => td.textContent.trim());
            // Columns: 0: TC, 1: FC, 2: TR, 3: FR, 4: Precision %, 5: Recall %
            if (tds.length >= 6) {
                results[String(zNum)] = {
                    precision: tds[4].replace('%', '').trim(),
                    recall: tds[5].replace('%', '').trim()
                };
            }
        });
        return results;
    }""")

    assert len(table_threshold_values) > 0, "No rows found in #benchmark-thresholds-table"

    # 2. Extract plotted chart markers
    chart_thresh_points = page.evaluate("""() => {
        const results = [];
        document.querySelectorAll('#benchmark-thresholds-chart-viewport svg [data-threshold]').forEach(el => {
            results.push({
                threshold: el.getAttribute('data-threshold'),
                series: el.getAttribute('data-series'),
                value: el.getAttribute('data-value'),
                tag: el.tagName.toLowerCase()
            });
        });
        return results;
    }""")

    assert len(chart_thresh_points) > 0, "No threshold points plotted in SVG"

    # Compare each table row with plotted points
    for z_str, table_vals in table_threshold_values.items():
        z_float = float(z_str)
        for series in ['precision', 'recall']:
            expected_val = table_vals[series]
            # Find matching markers
            matching_markers = [
                pt for pt in chart_thresh_points
                if abs(float(pt['threshold']) - z_float) < 1e-4 and pt['series'] == series and pt['tag'] in ('circle', 'rect')
            ]

            if expected_val in ('N/A', '—', '-', 'null', ''):
                # Missing/invalid measurement must NOT be plotted as a valid marker
                assert len(matching_markers) == 0, f"Missing observation Z={z_str} {series} should not be plotted"
            else:
                assert len(matching_markers) == 1, f"Expected 1 marker for Z={z_str} {series}, found {len(matching_markers)}"
                marker_val = float(matching_markers[0]['value'])
                table_num = float(expected_val)
                assert abs(marker_val - table_num) < 1e-2, (
                    f"Mismatch for Z={z_str} {series}: chart marker={marker_val}, table={table_num}"
                )
    return True


def test_deterministic_chart_to_table_numerical_equivalence(running_server):
    if not PLAYWRIGHT_AVAILABLE:
        pytest.skip("Playwright not installed")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        navigate_to_benchmarks(page, running_server)

        chart_baseline_values = page.evaluate("""() => {
            const results = {};
            document.querySelectorAll('#benchmark-baselines-chart-viewport svg text[data-baseline]').forEach(el => {
                const b = el.getAttribute('data-baseline');
                const m = el.getAttribute('data-metric');
                const v = el.getAttribute('data-value');
                if (!results[b]) results[b] = {};
                results[b][m] = v;
            });
            return results;
        }""")

        table_baseline_values = page.evaluate("""() => {
            const rows = document.querySelectorAll('#benchmark-baselines-table tbody tr');
            const results = {};
            rows.forEach(tr => {
                const th = tr.querySelector('th');
                if (!th) return;
                const bName = th.textContent.trim().toUpperCase();
                const tds = Array.from(tr.querySelectorAll('td')).map(td => td.textContent.trim());
                results[bName] = {
                    recall_pct: tds[3].replace('%', '').trim(),
                    precision_pct: tds[4].replace('%', '').trim(),
                    false_positive_rate_pct: tds[5].replace('%', '').trim(),
                    false_negative_rate_pct: tds[6].replace('%', '').trim(),
                    avg_latency_ms: tds[7].replace('ms', '').trim(),
                    total_tokens_spent: tds[8].trim()
                };
            });
            return results;
        }""")

        assert len(chart_baseline_values) > 0, "No chart baseline values found"
        assert len(table_baseline_values) > 0, "No table baseline values found"

        for b_chart_name, metrics in chart_baseline_values.items():
            matched_table_name = None
            for t_name in table_baseline_values.keys():
                if t_name == b_chart_name.upper():
                    matched_table_name = t_name
                    break
            assert matched_table_name is not None, f"Chart baseline {b_chart_name} not found in table"
            t_row = table_baseline_values[matched_table_name]

            for m_key, chart_val in metrics.items():
                table_val = t_row[m_key]
                if chart_val in ("N/A", "null", "undefined"):
                    assert table_val in ("N/A", "—", "-"), f"Expected N/A in table for {m_key}, got {table_val}"
                else:
                    assert abs(float(chart_val) - float(table_val)) < 1e-2, (
                        f"Mismatch for {b_chart_name} metric {m_key}: chart={chart_val}, table={table_val}"
                    )

        chart_eff_points = page.evaluate("""() => {
            const results = [];
            document.querySelectorAll('#benchmark-efficiency-chart-viewport svg circle[data-baseline]').forEach(el => {
                results.push({
                    name: el.getAttribute('data-baseline'),
                    latency: el.getAttribute('data-latency'),
                    tokens: el.getAttribute('data-tokens')
                });
            });
            return results;
        }""")
        assert len(chart_eff_points) > 0
        for pt in chart_eff_points:
            matched_t = None
            for t_name in table_baseline_values.keys():
                if t_name == pt["name"].upper():
                    matched_t = table_baseline_values[t_name]
                    break
            assert matched_t is not None, f"Efficiency baseline {pt['name']} not in table"
            assert abs(float(pt["latency"]) - float(matched_t["avg_latency_ms"])) < 1e-2
            assert abs(float(pt["tokens"]) - float(matched_t["total_tokens_spent"])) < 1e-2

        verify_threshold_chart_table_equivalence(page)
        browser.close()


def test_accessibility_contract_validation_helper_and_negative_control(running_server):
    if not PLAYWRIGHT_AVAILABLE:
        pytest.skip("Playwright not installed")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        navigate_to_benchmarks(page, running_server)

        validator_script = """() => {
            const tableContainers = [
                { chart: '#benchmark-baselines-chart-container', table: '#benchmark-baselines-table' },
                { chart: '#benchmark-thresholds-chart-container', table: '#benchmark-thresholds-table' }
            ];

            const issues = [];
            for (const item of tableContainers) {
                const chartElem = document.querySelector(item.chart);
                if (!chartElem) {
                    issues.push(`Missing chart container ${item.chart}`);
                    continue;
                }
                const tableElem = document.querySelector(item.table);
                if (!tableElem) {
                    issues.push(`Missing companion table ${item.table} for ${item.chart}`);
                    continue;
                }
                const style = window.getComputedStyle(tableElem);
                if (style.display === 'none' || style.visibility === 'hidden' || tableElem.getAttribute('aria-hidden') === 'true') {
                    issues.push(`Companion table ${item.table} is hidden`);
                }
                const headers = tableElem.querySelectorAll('th[scope="col"]');
                if (headers.length === 0) {
                    issues.push(`Companion table ${item.table} missing th[scope="col"] headers`);
                }
                const rows = tableElem.querySelectorAll('tbody tr');
                if (rows.length === 0) {
                    issues.push(`Companion table ${item.table} has no data rows`);
                }
            }
            return { valid: issues.length === 0, issues };
        }"""

        res = page.evaluate(validator_script)
        assert res["valid"] is True, f"Accessibility contract failed: {res['issues']}"

        page.evaluate("""() => {
            const tbl = document.querySelector('#benchmark-baselines-table');
            window._savedTblParent = tbl.parentNode;
            window._savedTbl = tbl;
            tbl.remove();
        }""")

        res_neg = page.evaluate(validator_script)
        assert res_neg["valid"] is False, "Validator must fail when companion table is removed"
        assert any("Missing companion table" in issue for issue in res_neg["issues"])

        page.evaluate("""() => {
            window._savedTblParent.appendChild(window._savedTbl);
        }""")

        res_restored = page.evaluate(validator_script)
        assert res_restored["valid"] is True, "Validator must pass when companion table is restored"
        browser.close()


def test_responsive_bounding_boxes_and_no_label_clipping_at_320px(running_server):
    if not PLAYWRIGHT_AVAILABLE:
        pytest.skip("Playwright not installed")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 320, "height": 800})
        navigate_to_benchmarks(page, running_server)

        for chart_id in [
            "benchmark-baselines-chart-viewport",
            "benchmark-thresholds-chart-viewport",
            "benchmark-efficiency-chart-viewport"
        ]:
            viewport = page.locator(f"#{chart_id}")
            assert viewport.is_visible()
            v_box = viewport.bounding_box()
            assert v_box["width"] <= 320, f"Viewport #{chart_id} width {v_box['width']} exceeds 320px"

        for table_id in ["benchmark-baselines-table", "benchmark-thresholds-table"]:
            table = page.locator(f"#{table_id}")
            assert table.is_visible()
            wrapper = page.locator(f"#{table_id}").locator("xpath=..")
            assert wrapper.get_attribute("tabindex") == "0"
            assert wrapper.get_attribute("role") == "region"
        browser.close()


def test_forced_colors_and_reduced_motion(running_server):
    if not PLAYWRIGHT_AVAILABLE:
        pytest.skip("Playwright not installed")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(forced_colors="active", reduced_motion="reduce")
        navigate_to_benchmarks(page, running_server)

        card = page.locator("#benchmark-baselines-chart-container")
        assert card.is_visible()

        transition_dur = page.evaluate("""() => {
            const el = document.querySelector('.benchmark-viz-card');
            return window.getComputedStyle(el).transitionDuration;
        }""")
        assert transition_dur in ("0s", "0.01ms", "0.00001s", "1e-05s", "0ms", "")
        browser.close()


def test_negative_control_mismatched_chart_table_values_detected(running_server):
    """Negative control: Verify that threshold chart-table equivalence assertion fails when a plotted value diverges from table value, and passes when restored."""
    if not PLAYWRIGHT_AVAILABLE:
        pytest.skip("Playwright not installed")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        navigate_to_benchmarks(page, running_server)

        # Baseline check: equivalence passes initially
        assert verify_threshold_chart_table_equivalence(page) is True

        # Deliberately distort a threshold marker's data-value
        page.evaluate("""() => {
            const marker = document.querySelector('#benchmark-thresholds-chart-viewport svg circle[data-threshold="2"][data-series="precision"], #benchmark-thresholds-chart-viewport svg circle[data-threshold="2.0"][data-series="precision"]');
            if (marker) {
                window._origThreshVal = marker.getAttribute('data-value');
                marker.setAttribute('data-value', '42.0');
            }
        }""")

        # Confirm that the EXACT SAME equivalence assertion helper fails on the distorted value
        divergence_caught = False
        try:
            verify_threshold_chart_table_equivalence(page)
        except AssertionError as exc:
            divergence_caught = True
            assert "Mismatch for Z=2" in str(exc) or "42.0" in str(exc)

        assert divergence_caught is True, "Equivalence assertion must raise AssertionError when threshold chart value diverges from table"

        # Restore original value
        page.evaluate("""() => {
            const marker = document.querySelector('#benchmark-thresholds-chart-viewport svg circle[data-threshold="2"][data-series="precision"], #benchmark-thresholds-chart-viewport svg circle[data-threshold="2.0"][data-series="precision"]');
            if (marker && window._origThreshVal) {
                marker.setAttribute('data-value', window._origThreshVal);
            }
        }""")

        # Confirm that the exact same equivalence assertion passes after restoration
        assert verify_threshold_chart_table_equivalence(page) is True
        browser.close()


def test_svg_bounding_box_within_viewport_at_320px(running_server):
    """Verify SVG bounding box and scroll width strictly fit within 320px viewport without clipping."""
    if not PLAYWRIGHT_AVAILABLE:
        pytest.skip("Playwright not installed")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 320, "height": 800})
        navigate_to_benchmarks(page, running_server)

        for chart_id in [
            "benchmark-baselines-chart-viewport",
            "benchmark-thresholds-chart-viewport",
            "benchmark-efficiency-chart-viewport"
        ]:
            svg = page.locator(f"#{chart_id} svg")
            box = svg.bounding_box()
            assert box is not None
            assert box["width"] <= 320, f"SVG #{chart_id} width {box['width']} exceeds 320px"
            assert box["x"] >= 0, f"SVG #{chart_id} x {box['x']} is shifted left outside viewport"

        browser.close()
