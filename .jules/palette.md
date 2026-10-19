# Palette's Journal - UX & Accessibility Learnings

## 2025-05-20 - Keyboard Accessibility & ARIA in Observatory UI
**Learning:** Icon-only and tab navigation buttons require explicit ARIA labels and roles, and interactive lists (like execution trace items) need proper keyboard event listeners (Enter/Space key support and `tabindex="0"`) alongside `aria-selected` attributes for accessibility.
**Action:** When adding or updating interactive controls in `epistemicos/ui/`, ensure focus indicators, keyboard activation listeners (`keydown` Enter/Space), and semantic ARIA states are present.
