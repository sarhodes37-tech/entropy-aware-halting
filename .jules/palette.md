# Palette's Journal - UX & Accessibility Learnings

## 2025-05-20 - Keyboard Accessibility & ARIA in Observatory UI
**Learning:** Icon-only and tab navigation buttons require explicit ARIA labels and roles, and interactive lists (like execution trace items) need proper keyboard event listeners (Enter/Space key support and `tabindex="0"`) alongside `aria-selected` attributes for accessibility.
**Action:** When adding or updating interactive controls in `epistemicos/ui/`, ensure focus indicators, keyboard activation listeners (`keydown` Enter/Space), and semantic ARIA states are present.

## 2026-11-02 - Bidirectional Cross-Surface Investigative Shortcuts
**Learning:** In investigative multi-view dashboards where evidence chains link across different explorer tabs (e.g. Execution Traces and Provenance Explorer), one-way navigation creates dead-ends. Providing symmetric bidirectional navigation shortcuts with descriptive ARIA labels (`aria-label="View provenance records for correlation ..."`) that pre-filter target views allows keyboard and screen reader users to trace audit events seamlessly without losing context.
**Action:** When linking related records across analytical or investigative views, implement symmetric quick-entry navigation triggers that filter the target surface and announce tab transitions via live regions.
