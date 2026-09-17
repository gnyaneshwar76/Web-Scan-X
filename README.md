# WebScanX

A local web vulnerability scanner. You download it, point it at a site you are
authorized to test, and it finds web vulnerabilities, explains each one in plain
language (what it is, how to check it, how to fix it) and exports one report.
v1 **finds and explains only** — it never changes your site. Everything runs on
your machine; nothing is uploaded.

## What's in here

| Folder | What it is |
| --- | --- |
| `webscanx/` | The engine: the Python scanner, its modules and the report writers. |
| `site/` | **The design, and the current source of truth.** React + Vite build of both surfaces: the Shop landing page and the local dashboard (New Scan, Scanning, Results, History, Settings, Export). Built in Figma Make. |
| `web/` | Earlier hand-written static prototype of the same two surfaces. Superseded by `site/`. |
| `design-preview/` | Offline HTML preview of the older Stitch screens. Reference only. |
| `DESIGN-BRIEF.md`, `STITCH-MASTER-PROMPT.md` | Design decisions and the screen-by-screen brief. |
| `sample_report.md`, `sample_report.html` | A real report produced by the engine. |

## Running the design

```bash
cd site
npm install
npm run dev
```

The Shop is at `/`, the dashboard at `#/dashboard/new-scan`.

## Design rules

- Dark only: background `#0D0C0C`, surface `#151414`, rules `#2A2828`.
- One accent, mint `#22D3A6`, used only for primary buttons and active states.
- One severity system on both surfaces, always colour **and** a text label:
  Critical `#FF3B30` (solid), High `#EF4444`, Medium `#F97316`, Low `#EAB308`,
  Info `#8A8A8A`.
- Space Grotesk for interface text, JetBrains Mono for anything technical.
- Sharp corners, thin rules, no shadows or gradients on interface elements.
- The Shop's sample report and the dashboard's Results screen are the same
  component with the same data — what a visitor is shown is what the tool gives.

## Status

The engine is in development. The download buttons on the Shop are placeholders
until there is a release to download.
