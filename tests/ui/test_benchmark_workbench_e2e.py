"""
Playwright E2E and visual verification test suite for the Benchmark Workbench (View 4).
Verifies run identity summary, condition comparison tables, McNemar inferential tests,
threshold sensitivity ablations, per-case inspection & filtering, clear-filter focus restoration,
hostile string XSS resilience, evidence availability state semantics, keyboard accessibility,
and responsive behavior without horizontal page overflow across viewports.
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
def benchmark_e2e_server(tmp_path):
    audit_file = tmp_path / "epistemic_audit.jsonl"
    provenance_file = tmp_path / "provenance_audit.jsonl"
    ablation_file = tmp_path / "ablation_table.json"
    per_case_file = tmp_path / "per_case_results.json"

    # Sample mock ablation table with baselines, McNemar comparisons, threshold ablations, and attribution
    mock_ablation = {
        "version": "2.1.0",
        "seed": 42,
        "run_id": "run-l4-20261030-xss_<script>alert('xss_run_id')</script>_test",
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

    # Sample per-case records with XSS payload and zero measurements
    mock_per_case = [
        {
            "run_id": "run-l4-20261030-xss_<script>alert('xss_run_id')</script>_test",
            "dataset_sha256_digest": "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678",
            "baseline": "Combined Gating",
            "case_id": "EVAL-001_<img src=x onerror=alert('xss_case_id')>",
            "scenario_family": "Cyber, Shell & DB Threat Vectors",
            "expected_outcome": "ROLLBACK",
            "actual_outcome": "ROLLBACK",
            "classification": "TR",
            "decision_reason": "PermissionGate: Blocked unauthorized command injection <script>alert('xss_reason')</script>",
            "latency_ms": 1.234,
            "tokens_consumed": 20
        },
        {
            "run_id": "run-l4-20261030-xss_<script>alert('xss_run_id')</script>_test",
            "dataset_sha256_digest": "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678",
            "baseline": "Ungated Generation",
            "case_id": "EVAL-002",
            "scenario_family": "Commercial Underwriting & Operations",
            "expected_outcome": "COMMIT",
            "actual_outcome": "COMMIT",
            "classification": "TC",
            "decision_reason": "Allowed",
            "latency_ms": 0.0,
            "tokens_consumed": 0
        }
    ]

    ablation_file.write_text(json.dumps(mock_ablation), encoding="utf-8")
    per_case_file.write_text(json.dumps(mock_per_case), encoding="utf-8")
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
def test_benchmark_workbench_e2e_and_responsiveness(benchmark_e2e_server):
    """E2E test verifying Benchmark Workbench sections, filters, focus restoration, XSS resilience, and responsive viewports."""
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

            # Dialog listener to catch any XSS execution
            dialogs = []
            page.on("dialog", lambda d: dialogs.append(d.message))

            page.goto(f"{benchmark_e2e_server}/index.html")

            # Click Benchmark Workbench tab
            page.click("#tab-benchmarks")
            page.wait_for_selector("#benchmark-run-summary-card")

            # Assert no XSS dialog fired
            assert len(dialogs) == 0, f"XSS script executed! Dialogs: {dialogs}"

            # Assert absence of horizontal page overflow
            assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), f"Horizontal page overflow detected at {vp['width']}px"

            # Check Run Identity Summary
            summary_card = page.locator("#benchmark-run-summary-card")
            assert summary_card.is_visible()

            # Check Condition Comparisons
            baselines_table = page.locator("#benchmark-baselines-tbody")
            assert baselines_table.is_visible()
            assert "Ungated Generation" in baselines_table.text_content()
            assert "Combined Gating" in baselines_table.text_content()

            # Check McNemar Comparisons Table
            mcnemar_tbody = page.locator("#benchmark-mcnemar-tbody")
            assert mcnemar_tbody.is_visible()
            assert "Combined Gating vs Ungated Generation" in mcnemar_tbody.text_content()

            # Check Threshold Sensitivity Table
            threshold_tbody = page.locator("#benchmark-thresholds-tbody")
            assert threshold_tbody.is_visible()
            assert "Z = 1.5" in threshold_tbody.text_content()

            # Check Per-Case Stream
            case_list = page.locator("#benchmark-case-list")
            assert case_list.is_visible()
            assert page.locator("#benchmark-case-list .trace-item").count() == 2

            # Test Per-Case Filtering & Clear Filters Focus Restoration
            search_input = page.locator("#benchmark-case-search")
            search_input.fill("nonexistent_search_query_123")
            page.wait_for_timeout(100)

            # Empty state message and Clear Case Filters button
            clear_btn = page.locator("button:has-text('Clear Case Filters')")
            assert clear_btn.is_visible()

            # Click Clear Case Filters
            clear_btn.click()
            page.wait_for_timeout(100)

            # Assert focus restored to search input
            assert page.evaluate("document.activeElement.id") == "benchmark-case-search"
            assert page.locator("#benchmark-case-list .trace-item").count() == 2

            # Test Case Selection and Detail Inspection
            first_case_item = page.locator("#benchmark-case-list .trace-item").first
            first_case_item.click()
            page.wait_for_selector("#benchmark-case-content")

            case_content = page.locator("#benchmark-case-content")
            assert case_content.is_visible()

            # Assert raw XSS payload rendered safely as string without execution
            assert "<img src=x onerror=alert('xss_case_id')>" in case_content.text_content()
            assert len(dialogs) == 0

            # Check Methodology & Limitations
            attribution_box = page.locator("#attribution-container")
            assert attribution_box.is_visible()
            assert "Entropy gate truncates" in attribution_box.text_content()

            unavailable_analyses = page.locator("#unavailable-analyses-container")
            assert unavailable_analyses.is_visible()
            assert "Statistical Power" in unavailable_analyses.text_content()

            context.close()

        browser.close()


@pytest.mark.skipif(not PLAYWRIGHT_AVAILABLE, reason="playwright not installed")
def test_benchmark_workbench_missing_artifacts_handling(tmp_path):
    """E2E test verifying explicit UNAVAILABLE state handling when benchmark artifacts are missing."""
    audit_file = tmp_path / "epistemic_audit.jsonl"
    provenance_file = tmp_path / "provenance_audit.jsonl"
    ablation_file = tmp_path / "missing_ablation.json"
    per_case_file = tmp_path / "missing_per_case.json"

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
        context = browser.new_context(viewport={"width": 1024, "height": 768})
        page = context.new_page()

        page.goto(f"{base_url}/index.html")
        page.click("#tab-benchmarks")

        page.wait_for_selector("#benchmark-artifacts-status")

        # Status badge should show UNAVAILABLE
        status_badge = page.locator("#benchmark-artifacts-status")
        assert "UNAVAILABLE" in status_badge.text_content()

        # Tables should display explicit unavailable text
        baselines_tbody = page.locator("#benchmark-baselines-tbody")
        assert "unavailable" in baselines_tbody.text_content().lower() or "not found" in baselines_tbody.text_content().lower()

        context.close()
        browser.close()

    server.shutdown()
    server.server_close()
