---
name: webscanx-report-style
description: "WebScanX HTML report visual style — Apple-like, dark-first, with a light/dark toggle"
metadata: 
  node_type: memory
  type: feedback
  originSessionId: a9047ca3-7aeb-4724-af74-7f81569c76bd
  modified: 2026-09-15T10:57:29.664Z
---

The WebScanX HTML report (`webscanx/report/render/__init__.py`, `to_html`) must feel
like an Apple product page, NOT a generated/templated dump. The rider rejected: flat
warm near-black ("dark biscuit"), bland stacked boxes, empty grid gaps.

Locked design decisions:
- **Apple aesthetic**: SF system font stack, pill-shaped controls, soft shadows (not
  hard borders), large rounded corners (18–22px), generous whitespace, restrained accent.
- **Dark-first, but BOTH themes** — a light/dark toggle (top-right) that honours the
  viewer's system preference and remembers the choice in localStorage. "someone likes
  light and someone likes dark." Never ship only one.
- **Interactive, not a picture**: live search, severity filter, expand/collapse per card
  + all, copy buttons on evidence, sticky toolbar, risk-score ring gauge, colored
  severity tiles. All self-contained (no CDN/fonts), local-first.
- Severity palette shared with the dashboard/shop [[webscanx-drive-stitch-directly]].

**Why:** the report is the client-facing deliverable and the visual template the live
dashboard will reuse — it has to look like a finished product.
**How to apply:** when editing the report renderer or building the dashboard, keep the
Apple + dual-theme + fully-interactive bar; verify rendered in a browser, don't ship
by screenshot-guessing. Engine vs report confusion recurs — engine = scanner in
`webscanx/scanners/`, report = its output in `webscanx/report/`.
