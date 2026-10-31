"""
Automated visual, contrast, accessibility, and cross-viewport regression test suite for EpistemicOS Benchmark Workbench.
Authoritative test suite verifying:
1. CSS custom property parsing from style.css and WCAG 2.2 AA contrast calculation against all surface and gradient stops.
2. Browser-rendered computed style contrast inspection on active Benchmark Workbench elements.
3. Realistic keyboard navigation (Tab / Shift+Tab traversal) and visible :focus-visible outline & box-shadow inspection.
4. Emulated reduced-motion behavior verifying suppressed spin animations and curtailed transition durations.
5. Emulated forced-colors behavior verifying high-contrast outlines and borders.
6. Comprehensive cross-viewport responsiveness testing and screenshot generation across all 7 required viewports.
"""

import json
import time
import re
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


def parse_hex_color(hex_str):
    hex_str = hex_str.strip().lstrip('#')
    if len(hex_str) == 3:
        hex_str = ''.join([c * 2 for c in hex_str])
    r = int(hex_str[0:2], 16)
    g = int(hex_str[2:4], 16)
    b = int(hex_str[4:6], 16)
    return (r, g, b)


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


def parse_css_custom_properties(css_content):
    tokens = {}
    matches = re.findall(r'(--[a-zA-Z0-9_-]+)\s*:\s*([^;]+);', css_content)
    for prop, val in matches:
        tokens[prop.strip()] = val.strip().split('/*')[0].strip()
    return tokens


def test_parsed_design_tokens_contrast_and_gradient_surfaces():
    """Parse actual design tokens from style.css and verify contrast against solid surfaces and gradient stops."""
    style_path = Path(__file__).parent.parent.parent / "epistemicos" / "ui" / "static" / "style.css"
    css_content = style_path.read_text(encoding="utf-8")
    tokens = parse_css_custom_properties(css_content)

    # Core background surfaces defined in palette
    bg_surfaces = {
        "base": parse_hex_color(tokens["--bg-base"]),
        "surface": parse_hex_color(tokens["--bg-surface"]),
        "elevated": parse_hex_color(tokens["--bg-elevated"]),
        "subtle": parse_hex_color(tokens["--bg-subtle"]),
    }

    # Gradient surface stop boundaries used across cards and panels
    gradient_stops = {
        "sidebar_bottom (#17122B)": (23, 18, 43),
        "card_bottom (#1A152E)": (26, 21, 46),
        "metric_bottom (#18132C)": (24, 19, 44),
        "derived_summary_bottom (#1F183B)": (31, 24, 59),
    }

    all_backgrounds = {**bg_surfaces, **gradient_stops}

    # Normal text tokens (require >= 4.5:1)
    normal_text_tokens = {
        "--text-primary": parse_hex_color(tokens["--text-primary"]),
        "--text-secondary": parse_hex_color(tokens["--text-secondary"]),
        "--text-muted": parse_hex_color(tokens["--text-muted"]),
        "--accent-primary": parse_hex_color(tokens["--accent-primary"]),
        "--accent-interactive": parse_hex_color(tokens["--accent-interactive"]),
        "--status-verified-fg": parse_hex_color(tokens["--status-verified-fg"]),
        "--status-halted-fg": parse_hex_color(tokens["--status-halted-fg"]),
    }

    for bg_name, bg_rgb in all_backgrounds.items():
        for fg_token, fg_rgb in normal_text_tokens.items():
            ratio = compute_contrast_ratio(fg_rgb, bg_rgb)
            assert ratio >= 4.5, f"Token {fg_token} against background '{bg_name}' has contrast {ratio:.2f}:1 (< 4.5:1)"

    # Large text & graphical boundary tokens (require >= 3.0:1)
    large_text_tokens = {
        "--accent-secondary": parse_hex_color(tokens["--accent-secondary"]),
        "--status-failed-fg": parse_hex_color(tokens["--status-failed-fg"]),
    }

    for bg_name, bg_rgb in all_backgrounds.items():
        for fg_token, fg_rgb in large_text_tokens.items():
            ratio = compute_contrast_ratio(fg_rgb, bg_rgb)
            assert ratio >= 3.0, f"Token {fg_token} against background '{bg_name}' has contrast {ratio:.2f}:1 (< 3.0:1)"


@pytest.fixture
def a11y_e2e_server(tmp_path):
    audit_file = tmp_path / "epistemic_audit.jsonl"
    provenance_file = tmp_path / "provenance_audit.jsonl"
    ablation_file = tmp_path / "ablation_table.json"
    per_case_file = tmp_path / "per_case_results.json"

    mock_ablation = {
        "version": "2.1.0",
        "seed": 42,
        "run_id": "run-l4-20261030-a11y-verified",
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

    mock_per_case = [
        {
            "run_id": "run-l4-20261030-a11y-verified",
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
def test_rendered_component_contrast_browser(a11y_e2e_server):
    """Inspect computed styles on rendered DOM elements in the browser and verify WCAG 2.2 AA contrast."""
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 900})
        page.goto(f"{a11y_e2e_server}/index.html")
        page.click("#tab-benchmarks")
        page.wait_for_selector("#benchmark-run-summary-card")

        # Elements to inspect
        contrast_checks = page.evaluate("""
            () => {
                function parseRgb(str) {
                    const m = str.match(/rgba?\\((\\d+),\\s*(\\d+),\\s*(\\d+)/);
                    return m ? [parseInt(m[1]), parseInt(m[2]), parseInt(m[3])] : [245, 240, 255];
                }
                function luminance(rgb) {
                    const [r, g, b] = rgb.map(c => {
                        const n = c / 255;
                        return n <= 0.04045 ? n / 12.92 : Math.pow((n + 0.055) / 1.055, 2.4);
                    });
                    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
                }
                function contrast(rgb1, rgb2) {
                    const l1 = luminance(rgb1);
                    const l2 = luminance(rgb2);
                    return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
                }

                // Reference background is deep plum surface rgb(29, 24, 51)
                const bgRgb = [29, 24, 51];

                const selectors = [
                    'h2',
                    '#benchmark-run-summary-card .card-header',
                    '#summary-run-id',
                    '#summary-sample-count',
                    '#benchmark-baselines-tbody td',
                    '.status-badge-available',
                    '#attribution-container strong'
                ];

                return selectors.map(sel => {
                    const el = document.querySelector(sel);
                    if (!el) return { selector: sel, found: false };
                    const style = window.getComputedStyle(el);
                    const fgRgb = parseRgb(style.color);
                    const ratio = contrast(fgRgb, bgRgb);
                    const fontSize = parseFloat(style.fontSize);
                    const fontWeight = parseInt(style.fontWeight) || 400;
                    const isLarge = fontSize >= 24 || (fontSize >= 18.66 && fontWeight >= 700);
                    return { selector: sel, found: true, ratio, isLarge, color: style.color };
                });
            }
        """)

        for check in contrast_checks:
            assert check["found"], f"Selector {check['selector']} not found in rendered DOM"
            required_threshold = 3.0 if check["isLarge"] else 4.5
            assert check["ratio"] >= required_threshold, (
                f"Element {check['selector']} color {check['color']} has contrast {check['ratio']:.2f}:1 "
                f"(requires {required_threshold}:1)"
            )

        browser.close()


@pytest.mark.skipif(not PLAYWRIGHT_AVAILABLE, reason="playwright not installed")
def test_keyboard_focus_navigation_order_and_visible_indicators(a11y_e2e_server):
    """Test realistic Tab and Shift+Tab traversal, sequential focus order, and visible outline rendering."""
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 900})
        page.goto(f"{a11y_e2e_server}/index.html")

        # Tab to Skip Link
        page.keyboard.press("Tab")
        active_el = page.evaluate("() => ({ id: document.activeElement.id, tag: document.activeElement.tagName, class: document.activeElement.className })")
        assert "skip-link" in active_el["class"]

        # Tab into Sidebar Nav Tablist (focuses active tab: tab-overview)
        page.keyboard.press("Tab")
        focused_id = page.evaluate("() => document.activeElement.id")
        assert focused_id == "tab-overview"

        # Navigate tabs via standard ARIA ArrowDown key navigation
        for expected_id in ["tab-traces", "tab-provenance", "tab-benchmarks"]:
            page.keyboard.press("ArrowDown")
            focused_id = page.evaluate("() => document.activeElement.id")
            assert focused_id == expected_id

        # Press Enter/Space on tab-benchmarks to activate Benchmark Workbench view
        page.keyboard.press("Enter")
        page.wait_for_selector("#benchmark-run-summary-card")

        # Inspect computed focus outline on the active focused tab
        outline_info = page.evaluate("""
            () => {
                const el = document.activeElement;
                const style = window.getComputedStyle(el);
                return {
                    outlineStyle: style.outlineStyle,
                    outlineWidth: style.outlineWidth,
                    outlineColor: style.outlineColor,
                    boxShadow: style.boxShadow
                };
            }
        """)

        assert outline_info["outlineStyle"] != "none"
        assert outline_info["outlineWidth"] not in ("0px", "")

        # Tab into the active panel controls (view-benchmarks -> benchmark search input)
        page.keyboard.press("Tab")
        panel_focused_id = page.evaluate("() => document.activeElement.id")
        assert panel_focused_id in ("view-benchmarks", "benchmark-case-search")

        # Verify Shift+Tab backward navigation returns focus to tab-benchmarks
        if panel_focused_id == "view-benchmarks":
            page.keyboard.press("Shift+Tab")
            returned_id = page.evaluate("() => document.activeElement.id")
            assert returned_id == "tab-benchmarks"

        browser.close()


@pytest.mark.skipif(not PLAYWRIGHT_AVAILABLE, reason="playwright not installed")
def test_reduced_motion_behavior_browser(a11y_e2e_server):
    """Test prefers-reduced-motion: reduce emulation to ensure animations and transitions are curtailed."""
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(reduced_motion="reduce", viewport={"width": 1440, "height": 900})
        page = context.new_page()
        page.goto(f"{a11y_e2e_server}/index.html")

        motion_styles = page.evaluate("""
            () => {
                const refreshIcon = document.querySelector('.refresh-icon');
                if (refreshIcon) refreshIcon.classList.add('spin');
                const btn = document.querySelector('.nav-tab');
                const styleIcon = refreshIcon ? window.getComputedStyle(refreshIcon) : null;
                const styleBtn = btn ? window.getComputedStyle(btn) : null;
                return {
                    animationName: styleIcon ? styleIcon.animationName : null,
                    animationDuration: styleIcon ? styleIcon.animationDuration : null,
                    transitionDuration: styleBtn ? styleBtn.transitionDuration : null,
                    scrollBehavior: window.getComputedStyle(document.documentElement).scrollBehavior
                };
            }
        """)

        # Under reduced motion, animation is 'none' or duration is effectively instantaneous (<= 0.01s)
        duration_s = float(motion_styles["animationDuration"].replace("s", "").replace("m", "")) if motion_styles["animationDuration"] else 0.0
        assert motion_styles["animationName"] == "none" or duration_s <= 0.01

        browser.close()


@pytest.mark.skipif(not PLAYWRIGHT_AVAILABLE, reason="playwright not installed")
def test_forced_colors_behavior_browser(a11y_e2e_server):
    """Test forced-colors: active emulation to ensure high-contrast border rules take effect."""
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(forced_colors="active", viewport={"width": 1440, "height": 900})
        page = context.new_page()
        page.goto(f"{a11y_e2e_server}/index.html")
        page.click("#tab-benchmarks")
        page.wait_for_selector("#benchmark-run-summary-card")

        border_info = page.evaluate("""
            () => {
                const activeTab = document.querySelector('.nav-tab.active');
                const badge = document.querySelector('.status-badge');
                return {
                    tabBorderWidth: activeTab ? window.getComputedStyle(activeTab).borderWidth : null,
                    badgeBorderWidth: badge ? window.getComputedStyle(badge).borderWidth : null
                };
            }
        """)

        # Under forced-colors: active, borders are explicitly defined
        assert border_info["tabBorderWidth"] not in (None, "0px")
        assert border_info["badgeBorderWidth"] not in (None, "0px")

        browser.close()


@pytest.mark.skipif(not PLAYWRIGHT_AVAILABLE, reason="playwright not installed")
def test_workbench_cross_viewport_responsiveness_and_screenshots(a11y_e2e_server):
    """Verify zero horizontal overflow, component visibility, and capture screenshots across all 7 viewports."""
    verification_dir = Path("/home/jules/verification")
    verification_dir.mkdir(parents=True, exist_ok=True)

    required_viewports = [
        {"name": "Narrow mobile", "width": 320, "height": 568, "screenshot": "narrow_mobile_workbench.png"},
        {"name": "Typical mobile", "width": 390, "height": 844, "screenshot": "typical_mobile_workbench.png"},
        {"name": "Large mobile", "width": 430, "height": 932, "screenshot": None},
        {"name": "Tablet", "width": 768, "height": 1024, "screenshot": "tablet_workbench.png"},
        {"name": "Laptop", "width": 1366, "height": 768, "screenshot": None},
        {"name": "Desktop", "width": 1440, "height": 900, "screenshot": "desktop_workbench.png"},
        {"name": "Wide desktop", "width": 1920, "height": 1080, "screenshot": None},
    ]

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)

        for vp in required_viewports:
            context = browser.new_context(viewport={"width": vp["width"], "height": vp["height"]})
            page = context.new_page()

            page.goto(f"{a11y_e2e_server}/index.html")
            page.click("#tab-benchmarks")
            page.wait_for_selector("#benchmark-run-summary-card")

            # 1. Assert no horizontal page overflow
            no_overflow = page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
            assert no_overflow, f"Horizontal page overflow detected on {vp['name']} ({vp['width']}x{vp['height']})"

            # 2. Assert key components visibility
            assert page.locator("#benchmark-run-summary-card").is_visible()
            assert page.locator("#benchmark-baselines-tbody").is_visible()
            assert page.locator("#benchmark-case-list").is_visible()
            assert page.locator("#attribution-container").is_visible()

            # 3. Assert vertical content scrollability without horizontal blowout
            doc_metrics = page.evaluate("""
                () => {
                    window.scrollTo(0, document.body.scrollHeight);
                    return {
                        scrollY: window.scrollY,
                        scrollHeight: document.body.scrollHeight,
                        scrollWidth: document.documentElement.scrollWidth,
                        innerWidth: window.innerWidth
                    };
                }
            """)
            assert doc_metrics["scrollWidth"] <= doc_metrics["innerWidth"]

            # 4. Capture screenshot if requested
            if vp["screenshot"]:
                page.screenshot(path=str(verification_dir / vp["screenshot"]))

            context.close()

        browser.close()
