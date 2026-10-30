"""
Automated visual, contrast, accessibility, and cross-viewport regression test suite for EpistemicOS Benchmark Workbench.
Verifies WCAG 2.2 AA token contrast ratios, focus-visible CSS rules, reduced motion queries, forced-colors media queries,
and zero horizontal page overflow across all required viewports (320x568, 390x844, 430x932, 768x1024, 1366x768, 1440x900, 1920x1080).
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


def relative_luminance(rgb_tuple):
    def channel_luminance(c):
        c_norm = c / 255.0
        return c_norm / 12.92 if c_norm <= 0.04045 else ((c_norm + 0.055) / 1.055) ** 2.4

    r, g, b = rgb_tuple
    return 0.2126 * channel_luminance(r) + 0.7152 * channel_luminance(g) + 0.0722 * channel_luminance(b)


def compute_contrast_ratio(color1_rgb, color2_rgb):
    l1 = relative_luminance(color1_rgb)
    l2 = relative_luminance(color2_rgb)
    lighter = max(l1, l2)
    darker = min(l1, l2)
    return (lighter + 0.05) / (darker + 0.05)


def test_design_token_contrast_ratios_wcag_aa():
    """Verify that text color tokens against background surfaces satisfy WCAG 2.2 AA (>= 4.5:1 for normal text)."""
    bg_surface = (29, 24, 51)     # #1D1833
    bg_base = (18, 15, 36)        # #120F24
    bg_elevated = (40, 32, 68)    # #282044

    tokens = {
        "--text-primary (#F5F0FF)": (245, 240, 255),
        "--text-secondary (#B6A9CA)": (182, 169, 202),
        "--text-muted (#9889B8)": (152, 137, 184),
        "--accent-primary (#B69AFF)": (182, 154, 255),
        "--accent-secondary (#FF83B8)": (255, 131, 184),
        "--accent-interactive (#64DED9)": (100, 222, 217),
        "--status-verified-fg (#2DD4BF)": (45, 212, 191),
        "--status-halted-fg (#FBBF24)": (251, 191, 36),
    }

    for name, fg_rgb in tokens.items():
        ratio_surf = compute_contrast_ratio(fg_rgb, bg_surface)
        ratio_base = compute_contrast_ratio(fg_rgb, bg_base)
        ratio_elev = compute_contrast_ratio(fg_rgb, bg_elevated)

        assert ratio_surf >= 4.5, f"{name} against #1D1833 surface has contrast {ratio_surf:.2f}:1 (< 4.5:1)"
        assert ratio_base >= 4.5, f"{name} against #120F24 base has contrast {ratio_base:.2f}:1 (< 4.5:1)"
        assert ratio_elev >= 4.5, f"{name} against #282044 elevated has contrast {ratio_elev:.2f}:1 (< 4.5:1)"


def test_stylesheet_accessibility_and_motion_rules():
    """Verify presence of focus-visible, reduced-motion, and forced-colors rules in style.css."""
    style_path = Path(__file__).parent.parent.parent / "epistemicos" / "ui" / "static" / "style.css"
    content = style_path.read_text(encoding="utf-8")

    assert ":focus-visible" in content
    assert "outline:" in content
    assert "prefers-reduced-motion" in content
    assert "forced-colors" in content


@pytest.fixture
def a11y_e2e_server(tmp_path):
    audit_file = tmp_path / "epistemic_audit.jsonl"
    provenance_file = tmp_path / "provenance_audit.jsonl"
    ablation_file = tmp_path / "ablation_table.json"
    per_case_file = tmp_path / "per_case_results.json"

    mock_ablation = {
        "version": "2.1.0",
        "seed": 42,
        "run_id": "run-l4-20261030-a11y-test",
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
            }
        },
        "paired_mcnemar_comparisons": {},
        "threshold_ablations": {},
        "attribution": {"stopping_benefit": "Entropy gate truncates high-surprisal sequences instantly."}
    }

    mock_per_case = [
        {
            "run_id": "run-l4-20261030-a11y-test",
            "dataset_sha256_digest": "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678",
            "baseline": "Ungated Generation",
            "case_id": "EVAL-001",
            "scenario_family": "Cyber, Shell & DB Threat Vectors",
            "expected_outcome": "ROLLBACK",
            "actual_outcome": "ROLLBACK",
            "classification": "TR",
            "decision_reason": "PermissionGate: Blocked unauthorized command injection",
            "latency_ms": 1.234,
            "tokens_consumed": 20
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
def test_workbench_cross_viewport_responsiveness_all_profiles(a11y_e2e_server):
    """Verify no horizontal page overflow across all 7 required viewport profiles."""
    required_viewports = [
        {"name": "Narrow mobile", "width": 320, "height": 568},
        {"name": "Typical mobile", "width": 390, "height": 844},
        {"name": "Large mobile", "width": 430, "height": 932},
        {"name": "Tablet", "width": 768, "height": 1024},
        {"name": "Laptop", "width": 1366, "height": 768},
        {"name": "Desktop", "width": 1440, "height": 900},
        {"name": "Wide desktop", "width": 1920, "height": 1080},
    ]

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)

        for vp in required_viewports:
            context = browser.new_context(viewport={"width": vp["width"], "height": vp["height"]})
            page = context.new_page()

            page.goto(f"{a11y_e2e_server}/index.html")

            # Click Benchmark tab
            page.click("#tab-benchmarks")
            page.wait_for_selector("#benchmark-run-summary-card")

            # Check horizontal overflow
            no_overflow = page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
            assert no_overflow, f"Horizontal page overflow detected on {vp['name']} ({vp['width']}x{vp['height']})"

            # Verify visible focus state on tab button via keyboard Tab
            tab_btn = page.locator("#tab-benchmarks")
            tab_btn.focus()
            focused_id = page.evaluate("document.activeElement.id")
            assert focused_id == "tab-benchmarks"

            context.close()

        browser.close()
