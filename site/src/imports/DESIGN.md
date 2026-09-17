# WebScanX — Landing Page Documentation

Complete record of the design: what the page contains, how it is built, the decisions
behind it, and everything discussed while making it.

---

## 1. What this is

A single-page marketing / portfolio landing page for **WebScanX**, a command-line web
vulnerability scanner written in Python. The page is a portfolio piece: it is meant to
demonstrate professional-grade frontend work to recruiters while accurately describing
the tool.

The tool itself (as described on the page):

> A command-line vulnerability scanner for targets you control. It crawls, probes with
> focused modules, and prints findings mapped to the OWASP Top 10 — no dashboard, no
> agent, no telemetry.

Status shown on the page: **v0.1 · in development · not yet released**.

---

## 2. Files

| File | What it is |
| --- | --- |
| `WebScanX Landing v4.dc.html` | The live source. Design Component: template + logic class. **This is the one to edit.** |
| `WebScanX/index.html` | Self-contained bundled build. Opens offline in any browser, no build step, no dependencies. |
| `WebScanX/WebScanX Landing v4.dc.html` | Copy of the source, saved alongside the build. |
| `webscanx-landing.html` | The bundled build at the project root (same as `WebScanX/index.html`). |
| `WebScanX Landing.dc.html`, `v2`, `v3` | Earlier iterations, kept for reference. |
| `_ds/modernist-…/` | The bound Modernist design system (stylesheet + component bundle). |

---

## 3. Version history

| Version | What changed |
| --- | --- |
| **v1** | First pass. Basic hero, static terminal block, standard section stack. Read as "normal web". |
| **v2** | Tightened type scale and grid; better use of the Modernist rules and flush-left alignment. |
| **v3** | 3D perspective tunnel behind the hero with a travelling red scan plane; parallax cursor tracking; dark ground. |
| **v4** (current) | Full studio treatment: fixed section navigator rail, top scroll-progress bar, film-grain overlay, cursor spotlight, numbered section hierarchy (01–04), interactive module selector with detail inspector, working severity filter on the findings table, roadmap cards with progress bars, oversized footer wordmark. |

---

## 4. Page structure — top to bottom

**Fixed / global layers**

1. **Film grain** — SVG `feTurbulence` noise tiled across the viewport at 5% opacity, `pointer-events: none`. Adds print texture so the flat black does not read as empty.
2. **Cursor spotlight** — a 620px radial accent glow that follows the pointer, fading in on first move.
3. **Scroll progress bar** — 2px accent bar pinned to the top of the viewport, width driven by scroll position.
4. **Section rail** — 72px-wide fixed left column with vertical uppercase section labels (Top / Modules / Findings / Install / Roadmap). The current section turns accent red. Year "2026" at the bottom. Hidden below 1180px, and the main column drops its 72px left padding.
5. **Sticky header** — brand mark (pulsing red square + "WebScanX"), nav links, and an outlined "Get it" button. Translucent with a 16px backdrop blur over a 2px bottom rule.

**Sections**

1. **Hero** (`#top`) — 94vh, content bottom-aligned.
   - Full-bleed `<canvas>` behind everything: a wireframe perspective corridor (two horizontal planes at ±7.5 units, converging depth lines, drifting particles) with a red scan plane travelling toward the camera on a loop, plus a faint accent horizon line. Cursor position eases the vanishing point for parallax. A vertical gradient fades the canvas into the page ground at the bottom.
   - Left: eyebrow ("Offensive tooling · Python 3.10+ · v0.1 dev"), the headline **SCAN / THE. / SURFACE** — third line in outlined (stroked, transparent-fill) type, the period in accent red — a 46ch description, and two CTAs (solid accent "Install the CLI", outlined "Read the modules").
   - Right: a live terminal panel. Ten scripted lines type out on a 400ms interval and loop, showing a real scan run against a local DVWA target, ending in "done in 11.4s — 6 findings". A blinking accent block cursor sits at the end.
2. **Ticker** — full-width accent red band scrolling XSS · SQL INJECTION · CSRF · OWASP TOP 10 · JSON REPORTS · NO TELEMETRY, doubled so the loop is seamless.
3. **Stat quad** — four equal cells divided by 2px rules: `3` scanner modules, `A01–A07` OWASP coverage, `11.4s` full run on DVWA, `JSON` machine-readable output.
4. **01 — Modules** — "Three probes, one pass."
   - Left: three selectable rows (XSS probe, SQLi probe, CSRF audit) with index number, name, and OWASP category. Hover or click selects; the active row tints and its type brightens.
   - Right: an inspector pane for the selected module — OWASP tag, description, a ruled list of what it checks, and the exact CLI invocation (`webscanx --target <url> --xss`).
5. **02 — Output** — "Findings, not noise."
   - A severity filter (All / High / Medium / Low) as segmented buttons; the active one fills accent red.
   - A four-column ruled table: severity (with a colour-coded square), finding, endpoint, OWASP ID. Six sample findings from a DVWA run. Rows highlight on hover.
   - A live count line: "Showing N of 6 findings · scan-2026-08-20.json".
6. **03 — Install** — "Three lines to a first scan." Left: a mono terminal block with the three commands (clone, install requirements, run). Right: a ruled requirements list (Python 3.10+, requests · beautifulsoup4, a target you are authorised to test).
7. **Ethics poster** — the one full-field red section. Display-grade type: *"Scan only what you own or have written permission to test."* followed by a note that unauthorised scanning is illegal in most jurisdictions, and that WebScanX ships pointed at a local DVWA instance and refuses to run without an explicit target flag.
8. **04 — Roadmap** — "Where it goes next." Four cards separated by 2px gaps, each with phase label, status, a progress bar, title and note: Core crawler (100%, done), Three modules (60%, in progress), Reporting (0%, planned), Packaging (0%, planned). Cards lift 6px on hover.
9. **Footer** — oversized `WEBSCANX` wordmark in near-invisible ink (`#201e1d`) up to 168px, project and status link columns, and a bottom bar rule with "WebScanX / Not yet released".

---

## 5. Design system

The page is bound to **Modernist** (`_ds/modernist-327a1c6c-bdcc-4722-9e4f-2e528c4c6ff4/`).

Rules followed:

- **Archivo** throughout, via `var(--font-heading)` / `var(--font-body)`. Monospace (`ui-monospace, Menlo`) only for terminal output, paths and commands.
- **Zero corner radius** anywhere.
- **2px rules** as the primary organising device — between every section, around every panel, under every table header.
- **Flush left** — every heading, paragraph and button label.
- **One accent**, `#ec3013`, used sparingly: the primary CTA, the active state, the scan plane, small emphasis. The one place it runs as a full field is the ethics poster.
- **Modular grid** — equal-width cells with visible structure (stat quad, roadmap quad, module split).

**Dark inversion.** The design system's default ground is light (`#f3f2f2`). This page runs
inverted on near-black — appropriate for a security tool, and it lets the red scan plane
and the wireframe corridor read. The ink ramp used:

| Token | Hex | Use |
| --- | --- | --- |
| Ground | `#0d0c0c` | Page background |
| Raised | `#100f0f` | Inspector pane, roadmap cards |
| Panel | `#171615` | Terminal blocks, active/hover row tint |
| Rule | `#201e1d` | The 2px dividers, footer wordmark |
| Rule (light) | `#2d2b2b` / `#444141` | Inner hairlines, inactive borders |
| Muted | `#605d5d` / `#7d7979` | Labels, secondary copy |
| Body | `#9b9797` / `#d7d3d3` | Paragraphs |
| Ink | `#edeaea` | Headings, primary text |
| Accent | `#ec3013` | Primary action, active state, scan plane |
| Accent light | `#ff9783` | Link hover, medium severity, OWASP tags |
| Accent bright | `#ff563c` | CTA hover, terminal prompt marks |

Type scale is fluid (`clamp()`) throughout: hero headline 54→150px, section headings
34→62px, module names 22→34px, footer wordmark 48→168px. Tight tracking on display sizes
(−0.035em to −0.055em), wide tracking (0.16–0.24em) on uppercase labels.

---

## 6. Interaction and motion

| Behaviour | How it works |
| --- | --- |
| Terminal typing | `setInterval` at 400ms advances a `shown` counter; the template renders `script().slice(0, shown)`. Loops back to zero at the end. |
| 3D corridor | `requestAnimationFrame` loop on a DPR-aware canvas. Points projected as `x·F/z`; horizontal lines scroll toward the camera; the scan plane's depth is `DEPTH − (t·8 mod DEPTH)` and lines within 2.4 units of it draw accent red at 2px. |
| Parallax | Pointer position is eased (`+= (target − current) · 0.045`) into the vanishing point, shifting up to 80px horizontally and 44px vertically. |
| Cursor spotlight | Pointer move sets a `transform: translate()` on the fixed glow element. |
| Scroll progress | Scroll listener writes a percentage width to the top bar. |
| Section rail | The same listener finds the last section whose top is above 40% of the viewport and re-renders the rail with that item in accent. |
| Reveal on scroll | `IntersectionObserver` at a 0.12 threshold adds `.in` to `.reveal` elements; a staggered `transition-delay` of `(i mod 4) · 70ms` gives a cascade. A 6s failsafe reveals everything regardless. |
| Module selector | Hover or click sets `state.active`; the inspector pane and all row colours derive from it. |
| Severity filter | `state.filter` filters the findings array; the count line updates. |
| Ticker | Pure CSS `translateX(0 → −50%)` on a doubled list, 30s linear infinite. |

**Reduced motion.** A single `@media (prefers-reduced-motion: reduce)` rule kills every
animation and transition and forces final opacity/transform state. The canvas loop checks
the same media query and never starts.

**Responsive.** Below 1180px the rail hides and the main padding collapses. Below 940px the
hero split, module grid and quads all reflow to fewer columns.

---

## 7. Technical notes

- Built as a **Design Component** (`.dc.html`): a template of inline-styled markup plus a
  `class Component extends DCLogic` logic class. No stylesheets beyond the design system,
  no CSS classes for layout — inline styles only, so the page paints while it streams.
- The only rules in `<helmet><style>` are the ones that cannot be inline: `@keyframes`,
  the body reset, `::selection`, `:focus-visible`, the reduced-motion override and the
  media queries.
- Repetition is handled by `<sc-for>`; all computed values (colours, active flags,
  handlers, filtered lists) come out of `renderVals()`.
- The bundled `index.html` inlines the stylesheet, the runtime and the noise texture — it
  is one file with no external requests except the Google Fonts link for Archivo.

---

## 8. Content status

Everything on the page is **placeholder-grade but plausible**: the module names, CLI flags,
findings, endpoints, timings and roadmap percentages are written to match a real DVWA scan
but have not been taken from an actual run. Swap in real values once the CLI is firmed up:

- The ten terminal lines in `script()`
- `MODULES` — names, descriptions, check lists, flags
- `FINDINGS` — the six sample rows
- `stats` — the four headline numbers
- `install` — the clone URL currently points at `github.com/gnyaneshwar76/Projects`
- `roadmap` — phase titles, notes, percentages and statuses

---

## 9. Where this stands

v4 is the current design. Two paths from here:

1. **Keep iterating the visuals** — a different motion language, a re-weighted colour
   hierarchy, a refined type scale.
2. **Lock v4** and move to building the actual WebScanX Python CLI, then replace the
   placeholder content with real output.

---

## 10. Appendix — session notes

Recorded from the working session so nothing is lost between chats.

### 10.1 What is actually on disk right now

`E:\WebScanX\` currently holds only:

- `index.html` (18 KB) — **the superseded green build**, not v4.
- `DESIGN.md` — this file.

The v4 files described in §2 arrived as `E:\Visual direction and page content.zip`,
which unpacks to `WebScanX/index.html` (264 KB bundled build) and
`WebScanX/WebScanX Landing v4.dc.html` (32 KB source). They have **not** been copied
into `E:\WebScanX\` yet. Nothing else from §2 — `webscanx-landing.html`, the v1–v3
iterations, `_ds/modernist-…/` — is present on this machine.

The Python CLI itself does not exist here either. `webscanx.py`, `requirements.txt` and
the sample report the pages describe are all still to be written.

### 10.2 The superseded green build

Worth keeping straight, because it is the file actually sitting in the folder and it is a
*different design direction*, not an earlier draft of the same one.

| | v4 (Modernist / red) | Old `index.html` (OLED / green) |
| --- | --- | --- |
| Ground | `#0d0c0c` near-black + film grain | `#080D1A` navy-black |
| Accent | `#ec3013` red, `#ff9783` salmon | `#22E07B` green, `#10B981` |
| Type | Archivo, 2px rules, wide uppercase tracking | JetBrains Mono + IBM Plex Sans |
| Hero | Split: `SCAN / THE. / SURFACE` beside a live terminal | Centred: "See what a scanner sees." |
| Motion | Perspective corridor + travelling scan plane | Cursor-reactive particle grid |
| Findings | 6, filterable, A01 / A03 / A05 | 3, static, A01 / A03 |
| Sections | Hero · ticker · stats · modules · findings · install · ethics · roadmap · footer | Hero · terminal · modules · findings · ethics · footer |
| Provenance | Modernist design system | Footer credits the `ui-ux-pro-max` skill + 21st.dev "Animated Hero" |

The green build's CTAs are inert and its GitHub link is `href="#"`. v4 fixes both: real
anchors, and a real clone URL in the install block.

### 10.3 Positioning shift between the two

v4 did not just restyle — the copy changed what the tool claims to be:

- Added **"no dashboard, no agent, no telemetry"** as the differentiator.
- Added **JSON / machine-readable output** as a headline stat.
- Added an honest **v0.1 · in development · not yet released** status, plus a roadmap that
  admits two of four phases are at 0%.
- Ethics section tightened from a paragraph to one display line, and given concrete
  technical backing: *refuses to run without an explicit target flag*. The green build's
  India IT Act reference was generalised to "illegal in most jurisdictions".
- The green build's "Built to learn how the attacks work — not to replace ZAP" framing was
  dropped in favour of a flatter, more confident product voice.

### 10.4 Open items

- Copy the v4 bundled build over `E:\WebScanX\index.html`, with the `.dc.html` source
  alongside it. **Not done yet.**
- The `.dc.html` source will not render standalone: it references `./support.js` and
  `_ds/modernist-327a1c6c-bdcc-4722-9e4f-2e528c4c6ff4/styles.css` + `_ds_bundle.js`,
  none of which are in the zip. Only the bundled `index.html` opens offline.
- Decide §9: keep iterating the visuals, or lock v4 and start the Python CLI.
- Every number on the page is still placeholder — §8 has the exact list to swap.
