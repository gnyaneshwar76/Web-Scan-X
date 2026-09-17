# WebScanX — Full Build Plan (Shop ✓ + Dashboard)

---

## PART 1 — Shop (COMPLETE)

The Shop landing page is fully built in `src/App.tsx`. Features delivered:
- Perspective-tilted hero product preview with live scan cockpit
- Animated marquee, OS platform switcher, copy-to-clipboard buttons
- Interactive findings table (click row → detail panel updates)
- FAQ `<details>` accordion, smooth-scroll nav, hover states everywhere
- All 10 sections: Nav → Hero → Statement → How it works → Sample report → What it checks → Why trust it → Download → FAQ → Footer

---

## PART 2 — Dashboard (TO BUILD)

### Context

The Dashboard is the tool's actual local interface — a multi-screen web app that would run at `localhost:8080` when the user downloads WebScanX. It is a completely separate web surface from the Shop, accessed by clicking "Try the dashboard →" in the Shop hero.

Design spec: `src/imports/STITCH-MASTER-PROMPT.md` sections A–G  
Real findings data: `src/imports/sample_report.md` (8 real findings from a live WebScanX scan)

Currently there is no router and no dashboard code at all. This plan adds everything.

---

### Architecture

Install `react-router-dom`. Use `HashRouter` (safe for Figma Make's static deployment — no server routing needed).

**Route map:**

| Route | Component | Notes |
|---|---|---|
| `/` | `ShopPage` | Current App.tsx content, extracted |
| `/dashboard` | redirect → `/dashboard/new-scan` | |
| `/dashboard/new-scan` | `NewScan` | Default screen |
| `/dashboard/scanning` | `Scanning` | |
| `/dashboard/results` | `Results` | Most important — matches Shop sample report |
| `/dashboard/history` | `History` | |
| `/dashboard/settings` | `Settings` | |

All dashboard routes share `DashboardShell` (sidebar layout wrapper) via nested routing.

---

### File structure to create

```
src/
├── App.tsx                          ← Router root only (tiny)
├── pages/
│   ├── ShopPage.tsx                 ← Current App.tsx content moved here
│   └── dashboard/
│       ├── DashboardShell.tsx       ← Sidebar + <Outlet>
│       ├── NewScan.tsx              ← Screen B
│       ├── Scanning.tsx             ← Screen C
│       ├── Results.tsx              ← Screen D (most important)
│       ├── History.tsx              ← Screen E
│       ├── Settings.tsx             ← Screen G
│       └── ExportModal.tsx          ← Screen F (modal overlay on Results)
├── components/
│   ├── CopyButton.tsx               ← Already exists
│   └── SevPill.tsx                  ← Extract from ShopPage (used in both surfaces)
└── data/
    └── findings.ts                  ← Real findings from sample_report.md
```

---

### Screen-by-screen spec

#### A. DashboardShell (`src/pages/dashboard/DashboardShell.tsx`)

Fixed 240px left sidebar + main content area (`<Outlet />`).

**Sidebar contents (top to bottom):**
- **Wordmark:** "WebScanX" in `JetBrains Mono`, bold, + tag `LOCAL · v1.0` in muted mono below
- **Nav items** (with thin 1.5px line SVG icons, Lucide-style):
  - `New Scan` → `/dashboard/new-scan`
  - `Results` → `/dashboard/results`
  - `History` → `/dashboard/history`
  - `Settings` → `/dashboard/settings`
  - Active item: 2px accent left bar + primary text color; inactive: muted text, hover → secondary text
- **Bottom:** status chip `● Offline-safe — nothing leaves this device` (muted text, small) + `localhost:8080` in mono below it

**Main area:** `bg-[#0d0c0c]`, overflows vertically, padding `px-8 py-8`.

---

#### B. NewScan (`src/pages/dashboard/NewScan.tsx`)

Two-column layout: centered form (max 640px) left, "Recent targets" list right.

**Form fields (top to bottom):**
1. **Target input** — label "Target", large mono `<input>`, placeholder `https://staging.example.com`, full-width, `bg-surface border border-rule`. Shows inline error `"Enter a full URL including https://"` if submitted empty.
2. **Scan depth** — segmented control, 3 options:
   - `Quick` (~2 min) — headers and TLS only
   - `Standard` (~10 min) — all modules, standard depth  ← default selected
   - `Deep` (~45 min) — all modules, deep crawl
   Active option: `bg-accent text-[#0d0c0c]`; inactive: `bg-surface text-secondary-text border border-rule`
3. **Modules checklist** — 5 items, all checked by default: Security headers, TLS / certificates, XSS, SQL injection, CSRF. Mono checkbox style, `accent-[#22d3a6]`.
4. **Authorization gate** — prominent bordered box (`border border-rule bg-surface p-4`):
   - Checkbox: `☐ I am authorized to scan this target`
   - Secondary text below: `"Scanning systems you don't own or have written permission to test may be illegal."`
   - **This box is visually important — not buried.** Large checkbox, clear label.
5. **Start Scan button** — full-width, accent when auth checked, dimmed (`opacity-40 cursor-not-allowed`) when unchecked. `useState` controls both the button state and whether clicking is allowed.

**Recent targets** (right column, muted, 160px wide):
- Label: `RECENT TARGETS` in muted mono uppercase
- 3 mono URLs: `https://staging.example.com`, `https://demo.webscanx.internal`, `http://127.0.0.1:8000`
- Clicking a URL fills the target input (React state)

**Navigation on Start:** clicking Start Scan (when enabled) navigates to `/dashboard/scanning` via `useNavigate`.

---

#### C. Scanning (`src/pages/dashboard/Scanning.tsx`)

Shows a live scan in progress. All data is static/simulated (no real network calls).

**Top bar:**
- Mono target URL: `https://staging.example.com`
- Depth badge: `STANDARD` (mono, surface bg, rule border)
- Elapsed: `04:12` (mono)
- `Stop scan` button (outlined, secondary — **not** accent)

**Progress:**
- Thin full-width accent progress bar at 62%
- Below: mono text `Checking: XSS — reflected parameters (38 / 61 requests)` + `62%` right-aligned in accent

**Module states row:**
- `✓ Security headers` (done, muted)
- `✓ TLS / certificates` (done, muted)
- `◐ XSS` (running, accent text + accent left border)
- `○ SQL injection` (queued, muted)
- `○ CSRF` (queued, muted)

**Live counters row:** 5 SevPill + count: `CRITICAL 0`, `HIGH 2`, `MEDIUM 3`, `LOW 5`, `INFO 8`

**Live findings feed** (newest first, `space-y-1.5`):
Each row: SevPill, finding name, mono path, mono timestamp
5 rows matching real data from `findings.ts`

**"View results" button:** accent, navigates to `/dashboard/results`. Shown when scan is logically "done" (for demo purposes, show it immediately as a secondary option below the feed with label "Scan complete — view full report →")

**Raw log panel** (collapsible via `<details>`): terminal-style, mono 11px, dim text, scrollable, 5–6 realistic log lines.

---

#### D. Results (`src/pages/dashboard/Results.tsx`) — most important screen

Split layout: findings table 60% left + detail panel 40% right.

**Header:**
- Mono: `TARGET: http://127.0.0.1:63725/`
- `DATE: 15 Sep 2026`, `DURATION: 0m 0s` (from real scan data)
- Stacked severity bar: proportional segments for 3H / 2M / 3L / 0I
- Labels: `3 High · 2 Medium · 3 Low`
- Export button (outlined): opens `ExportModal`

**Filter tabs:**
- `All (8)` / `High (3)` / `Medium (2)` / `Low (3)` — `useState` filters the table
- Search input (filters by finding name)

**Findings table** — real data from `findings.ts`:
All 8 findings from `sample_report.md`:

| # | Sev | Name | Path | Module | Status |
|---|---|---|---|---|---|
| 1 | HIGH | Site served over HTTP (no TLS) | `http://127.0.0.1:63725` | TLS | New |
| 2 | HIGH | Reflected XSS | `/?q=hello` | XSS | New |
| 3 | HIGH | SQL injection (error-based) | `/?q=hello` | SQLI | New |
| 4 | MEDIUM | Missing Content-Security-Policy | `/` | HEADERS | New |
| 5 | MEDIUM | Form without anti-CSRF token | `/login` | CSRF | New |
| 6 | LOW | Missing X-Content-Type-Options | `/` | HEADERS | Seen |
| 7 | LOW | Missing X-Frame-Options | `/` | HEADERS | Seen |
| 8 | LOW | Missing Referrer-Policy | `/` | HEADERS | Seen |

Row click → `selectedIdx` state → detail panel updates. Row 1 selected by default (accent left bar).

**Detail panel** (for selected finding) — sections with mono uppercase headings:
- **WHAT IT IS** — plain language from `findings.ts`
- **HOW TO CHECK IT YOURSELF** — steps + copyable mono curl command (uses `CopyButton`)
- **EVIDENCE** — mono block with the actual evidence from `sample_report.md`
- **HOW TO FIX IT** — plain steps
- **REFERENCES** — scanner module + OWASP tag + CWE

---

#### E. History (`src/pages/dashboard/History.tsx`)

**Header:** title `History`, muted note `Stored locally in ~/.webscanx/scans`

**Controls:** search input + `Compare two scans` secondary button (non-functional for now)

**Table** (8 past scans, mix of real + plausible fabricated):
Columns: Date, Target (mono), Depth, Duration, Findings (mini stacked severity bar + counts), Actions (Open → `/dashboard/results`, Export → opens `ExportModal`, Delete icon)

Use the real scan data as row 1 (2026-09-15, `http://127.0.0.1:63725/`, Standard, 0m, 3H/2M/3L). Fabricate 7 plausible past scans with varied targets and finding counts.

---

#### F. ExportModal (`src/pages/dashboard/ExportModal.tsx`)

Modal overlay (fixed, backdrop `bg-[#0d0c0c]/80 backdrop-blur-sm`). Rendered conditionally from Results and History via props/state.

**Contents:**
- Title: `Export report`
- 4 format cards (selectable, `useState`): `PDF` "Share with a client", `Markdown` "Paste into a ticket", `HTML` "Open in any browser", `JSON` "Feed into other tools". Selected card: accent border.
- Toggles (3): Include evidence, Include ignored findings, Redact target hostname
- Output path in mono: `~/Documents/webscanx-report-2026-09-14.pdf` + `Change` link (non-functional)
- Buttons: `Cancel` (text, closes modal) + `Export` (accent, closes modal after 500ms simulated delay)

---

#### G. Settings (`src/pages/dashboard/Settings.tsx`)

Sections divided by 1px rules:

1. **Default scan depth** — same segmented control as NewScan (`useState` persists in `localStorage`)
2. **Default modules** — same 5-item checklist, all checked by default
3. **Report folder** — mono path `~/Documents/webscanx-reports/` + `Change` button (non-functional)
4. **Request rate limit** — mono number input `14` with label `req/sec`
5. **Theme** — note `Dark only` (no toggle)

`Save` button (accent, full-width) at bottom. Shows `✓ Saved` for 2s then resets (same pattern as `CopyButton`).

---

### Shared component: SevPill (`src/components/SevPill.tsx`)

Extract from current `App.tsx` (currently defined inline). Used in both Shop and Dashboard.

```tsx
type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

const colors = {
  CRITICAL: "bg-[#ff3b30] text-[#0d0c0c]",          // solid fill
  HIGH:     "bg-[#ef4444]/15 text-[#ef4444]",
  MEDIUM:   "bg-[#f97316]/15 text-[#f97316]",
  LOW:      "bg-[#eab308]/15 text-[#eab308]",
  INFO:     "bg-[#8a8a8a]/15 text-[#8a8a8a]",
};
```

---

### Shared data: findings (`src/data/findings.ts`)

Export a typed `Finding[]` array with all 8 real findings from `sample_report.md`. Each finding:

```ts
type Finding = {
  id: number;
  severity: "HIGH" | "MEDIUM" | "LOW" | "INFO";
  name: string;
  path: string;
  module: string;
  status: "New" | "Seen" | "Ignored";
  what: string;
  howToCheck: string;
  checkCommand: string;
  evidence: string;
  fix: string;
  refs: string;          // e.g. "web.xss · A05:2025 · CWE-79"
};
```

---

### Wiring the Shop → Dashboard

In `src/pages/ShopPage.tsx` (the extracted Shop):
- Hero "Try the dashboard →" text → `<Link to="/dashboard">` (React Router `Link`)
- Shop Nav has no direct link to dashboard (it's a separate app; user downloads and runs locally)

---

### Step-by-step execution order

1. Install `react-router-dom` (`pnpm add react-router-dom`)
2. Create `src/data/findings.ts` with all 8 real findings
3. Create `src/components/SevPill.tsx` (extracted from App.tsx)
4. Move current `App.tsx` content → `src/pages/ShopPage.tsx`, update `SevPill` import
5. Rewrite `src/App.tsx` as router root with `HashRouter`
6. Create `src/pages/dashboard/DashboardShell.tsx`
7. Create dashboard screens: `NewScan` → `Scanning` → `Results` → `History` → `Settings` → `ExportModal`
8. Wire Shop hero "Try the dashboard →" to `<Link to="/dashboard">`
9. TypeScript check — fix any errors

---

### Verification

1. `/` loads the Shop — all existing functionality intact.
2. Clicking "Try the dashboard →" in the Shop hero navigates to `/dashboard/new-scan`.
3. Sidebar visible on all dashboard screens with correct active state per route.
4. NewScan: Start Scan button disabled until authorization checkbox checked; clicking navigates to Scanning.
5. Results: all 8 real findings shown; clicking a row updates the detail panel with correct WHAT/HOW/EVIDENCE/FIX.
6. Filter tabs filter the findings list correctly.
7. Export button opens modal; Cancel closes it.
8. History table shows 8 rows.
9. Settings Save button shows ✓ Saved feedback.
10. Browser back/forward navigation works correctly (HashRouter).
