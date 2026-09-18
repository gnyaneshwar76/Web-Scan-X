# WebScanX — Design handoff (the "car" track)

Read this to continue the DESIGN work in a new chat. The ENGINE (Python scanner) is a
separate track — see the `webscanx-project-state` memory file for that.

Last updated: 18 Sep 2026.

---

## What WebScanX is (one paragraph)

A local security scanner. The client downloads it, points it at a target they are
**authorized** to test, and it finds web vulnerabilities, explains each in plain
language (what it is / how to check it / evidence / how to fix it) and exports one
report. v1 **finds and explains only** — no auto-fix. Selling point: everything runs
on the device, nothing is uploaded.

---

## Where the design lives now

| Thing | Where | Status |
| --- | --- | --- |
| **Design source of truth** | `site/` in the repo (React + Vite + Tailwind v4) | **Current.** Both surfaces, all screens. |
| Figma Make project | Figma Make, deployed at https://rename-slot-39298091.figma.site/ | The design is authored here, exported as a zip, and copied into `site/`. |
| Figma design file (components + tokens) | https://www.figma.com/design/KV2plgQwDWEyVa2U4lUqmd — account gnyaneshwar76@gmail.com, team "Andriod studio" | Hand-built library: colour variables, text styles, Severity Pill, Button, Nav Item, Sidebar, Finding Row, Report; plus Shop and Dashboard pages. |
| Old Figma file | `447VIKWD8zSfF9TrPTjQji` under 2310030058@klh.edu.in | Same content, wrong account. Delete when convenient. |
| `web/` | Repo | Earlier hand-written static prototype (plain HTML/CSS/JS, fully working). Superseded by `site/`, kept for reference. |
| `design-preview/WebScanX-Design.html` | Repo | Offline preview of the old Stitch screens. Reference only. |
| `STITCH-MASTER-PROMPT.md`, `STITCH-PROMPTS.md`, `DESIGN.md` | Repo | Historical. Stitch drafts and the old v4 landing page. Do not build from these. |

**Workflow now:** edit in Figma Make → export the zip → unzip over `site/` → check the
diff → commit → push. Any fix made directly in `site/` must also be made in Figma Make,
or the next export undoes it.

---

## Locked decisions (do not re-litigate)

- **Two surfaces:** the **Shop** (public marketing/download page) and the **Dashboard**
  (the tool's own interface, would run at `localhost:8080`). They never talk to each
  other at runtime; the site only offers the download.
- **Dark only.** Background `#0D0C0C`, surface `#151414`, raised `#1C1B1B`,
  rules `#2A2828`, text `#F2F0EF`, secondary `#9A9695`, muted `#605D5D`.
- **One accent: mint `#22D3A6`**, only for primary buttons, active nav/tab, focus rings
  and progress. Never for severity. (Red was rejected because red is the High/Critical
  severity colour.)
- **One severity system on both surfaces,** always colour **and** a text label:
  Critical `#FF3B30` (solid fill, dark text), High `#EF4444`, Medium `#F97316`,
  Low `#EAB308`, Info `#8A8A8A` (each as a 12% tint with coloured text).
- **Two typefaces:** Space Grotesk for interface text, JetBrains Mono for every
  technical value (URLs, paths, payloads, code, counts, timestamps, checksums).
- **Shape:** 0–2px radius, thin 1px rules, no shadows, no gradients on interface
  elements, no glassmorphism, no pill buttons.
- **Scope in all copy:** web targets, finds-and-explains only. Never say auto-fix,
  cloud, AI, or code/dependency scanning on the Shop.
- **The Shop's sample report and the Dashboard's Results screen are the same component
  with the same data.** This is the main trust-builder; keep it true.

---

## What is built (all of it, in `site/`)

**Shop** — `src/pages/ShopPage.tsx`, one long page: nav → hero (headline,
platform-aware download button, live scan preview) → statement + marquee → how it works
(3 steps) → sample report (interactive) → what it checks (5) → why trust it (4) →
download (3 platforms + pip + checksums) → FAQ → footer.

**Dashboard** — `src/pages/dashboard/`, hash-routed from `src/App.tsx`:

| Route | File | Notes |
| --- | --- | --- |
| `#/dashboard/new-scan` | `NewScan.tsx` | Target input with validation, depth, modules, **authorization gate** (Start stays disabled until ticked). |
| `#/dashboard/scanning` | `Scanning.tsx` | Progress, per-module state, severity counters, live findings, log. |
| `#/dashboard/results` | `Results.tsx` | The report: severity bar, filters, findings table, detail panel (what / evidence / fix / refs). |
| `#/dashboard/history` | `History.tsx` | Past scans, mini severity bars, open / export / delete. |
| `#/dashboard/settings` | `Settings.tsx` | Defaults, folders, request rate, timeout. |
| (modal) | `ExportModal.tsx` | PDF / Markdown / HTML / JSON plus options. |

**Shared:** `src/data/findings.ts` (the single findings dataset, `SEV_COLORS`,
`SCAN_META`), `src/components/SevPill.tsx`, `src/components/CopyButton.tsx`,
`src/index.css` (tokens and utilities).

The findings data is a **real engine report** (8 findings: 3 High, 2 Medium, 3 Low, on
`http://127.0.0.1:63725/`), not invented. It came from `sample_report.md` in the repo
root.

---

## How to run

```bash
cd site
pnpm install
pnpm run dev
```

`site/.figma/make/site.json` (page title, description, language) is **not** part of the
Figma Make zip export — without it `vite.config.ts` fails to load and the dev server will
not start. It is committed now; keep it, and re-check it after every export.

Shop at `/`, dashboard at `#/dashboard/new-scan`.

---

## Known gaps / next steps

1. **Fixes made in `site/` are not yet back in Figma Make.** Re-apply all of these in
   Figma Make before the next export, or the next export undoes them:
   - the severity colours in `index.css` (`--color-sev-*`, `.sev-border-*`) and the
     error / delete-hover reds in `NewScan.tsx` and `History.tsx`;
   - the whole **mobile pass** below (`DashboardShell.tsx`, `Results.tsx`,
     `Scanning.tsx`, `History.tsx`, `Settings.tsx`).
2. **Download buttons are placeholders** — there is no built binary yet.
3. ~~Mobile layout has not been reviewed.~~ **Done, 18 Sep 2026.** Reviewed at 375×812
   on the real `site/` build; every route now has zero horizontal page overflow and
   desktop is unchanged (all fixes are `md:`-gated). What changed:
   - `DashboardShell.tsx` — the 200px sidebar is `hidden md:flex`. Below `md` the brand
     block becomes a top bar and the same `NAV` array renders as a bottom tab bar.
   - `Results.tsx` — the findings list and the detail panel stack (`flex-col md:flex-row`);
     the list gets `max-h-[45%]` and a bottom rule instead of the right rule.
   - `Scanning.tsx` — the target header wraps and the URL truncates.
   - `History.tsx` — the fixed-width table sits in an `overflow-x-auto` /
     `min-w-[560px]` scroller so the Target column stays readable; the filter row wraps.
   - `Settings.tsx` — label/control rows stack below `md`; page gutter `px-5 md:px-8`.
4. The Figma component file and `site/` can drift. The Figma file is for design and
   handoff; `site/` is what ships.
5. Old files (`web/`, `design-preview/`, `index.html`, the Stitch docs) can be deleted
   once nobody needs the reference.

---

## Repo

https://github.com/gnyaneshwar76/Web-Scan-X — branch `main`, local clone `E:\WebScanX`
in sync. Pushing works with the cached Windows credential:
`cd /e/WebScanX && git add -A && git commit -m "msg" && git push`
