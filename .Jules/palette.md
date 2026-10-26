## 2025-05-18 - WAI-ARIA Tab Panel & Roving Tabindex Accessibility
**Learning:** Tabbed interfaces in web dashboards with `role="tablist"` require proper `role="tabpanel"` markup with `aria-labelledby` referencing the tab element, `tabindex="0"` on tabpanels for keyboard focusability, and roving `tabindex="0"` / `tabindex="-1"` on tab buttons combined with Left/Right arrow key navigation for WCAG / WAI-ARIA compliance.
**Action:** When implementing tabbed UI navigation, ensure roving tabindex and arrow key event handlers are bound on the tablist elements and tabpanels are explicitly labeled.

## 2025-05-18 - Clickable Table Rows Keyboard Accessibility
**Learning:** Dynamic table rows with `class="clickable"` acting as navigation triggers require explicit `tabindex="0"`, `role="button"`, descriptive `aria-label`, and `keydown` event listeners for `Enter` and `Space` keys so screen reader and keyboard-only users can discover, focus, and activate table actions.
**Action:** When creating interactive dynamic table rows, always pair click listeners with `tabindex="0"`, `role="button"`, `aria-label`, keydown handlers, and `.data-table tr.clickable:focus-visible` styling.
