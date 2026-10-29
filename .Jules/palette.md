## 2025-05-18 - WAI-ARIA Tab Panel & Roving Tabindex Accessibility
**Learning:** Tabbed interfaces in web dashboards with `role="tablist"` require proper `role="tabpanel"` markup with `aria-labelledby` referencing the tab element, `tabindex="0"` on tabpanels for keyboard focusability, and roving `tabindex="0"` / `tabindex="-1"` on tab buttons combined with Left/Right arrow key navigation for WCAG / WAI-ARIA compliance.
**Action:** When implementing tabbed UI navigation, ensure roving tabindex and arrow key event handlers are bound on the tablist elements and tabpanels are explicitly labeled.

## 2025-05-18 - Clickable Table Rows Keyboard Accessibility
**Learning:** Dynamic table rows with `class="clickable"` acting as navigation triggers require explicit `tabindex="0"`, `role="button"`, descriptive `aria-label`, and `keydown` event listeners for `Enter` and `Space` keys so screen reader and keyboard-only users can discover, focus, and activate table actions.
**Action:** When creating interactive dynamic table rows, always pair click listeners with `tabindex="0"`, `role="button"`, `aria-label`, keydown handlers, and `.data-table tr.clickable:focus-visible` styling.

## 2025-05-18 - Dynamic ARIA Label Updates for Interactive Action Feedback
**Learning:** When interactive elements (such as copy buttons) have an explicit `aria-label` attribute, screen readers prioritize `aria-label` over `textContent`. Changing `textContent` to "Copied!" will be silent to screen readers unless `aria-label` is dynamically updated during feedback states and restored upon timeout.
**Action:** When implementing button action feedback, always capture the original `aria-label`, update `aria-label` dynamically during the feedback window (e.g. "Copied to clipboard!"), and restore the original `aria-label` when the feedback resets.

## 2025-05-18 - Table Row Selection Accessibility and Visual Indicators
**Learning:** Selectable table rows in detailed timeline or stream views require explicit `aria-selected` boolean states ('true'/'false') alongside active visual selection classes (such as elevated background and left border accent indicators) to ensure screen reader users receive selection state updates when clicking or navigating table events.
**Action:** When rendering selectable table rows, always bind `aria-selected` dynamically to match selection state and apply `.data-table tr.clickable.selected` CSS styling.

## 2025-05-18 - Human-Readable ARIA Labels for Dynamic Helper Buttons
**Learning:** Using raw DOM element IDs (like `summary-dataset-digest`) inside dynamic button `aria-label` attributes causes screen readers and tooltips to announce internal technical identifiers rather than clear, user-facing descriptive labels.
**Action:** When creating reusable UI helper functions that set `aria-label` or `title` attributes on dynamic action buttons, accept an explicit human-readable label parameter to ensure screen readers announce accessible titles (e.g. "Copy Dataset SHA-256 Digest").

## 2025-05-18 - Focus Restoration Upon Dynamic Control Destruction
**Learning:** When a user clicks a dynamic button inside an empty state container (such as "Clear Filters") that subsequently destroys or removes the button from the DOM during list re-rendering, keyboard focus drops to `document.body` or is lost entirely. Explicitly calling `focus()` on the corresponding search input upon resetting search/filter state preserves logical focus context for keyboard navigation.
**Action:** When destroying dynamic action triggers during state reset or list re-rendering, explicitly transfer focus to a logical persistent anchor element (such as the search input).
