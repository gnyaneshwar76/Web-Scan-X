> HISTORICAL — superseded by the Figma Make design in `site/`. Kept for reference only.
> Current design handoff: DESIGN-BRIEF.md

# WebScanX — Stitch Master Prompt (one go)

Open a NEW Stitch project (Web / desktop). Paste the whole block below as the first
message. When the Shop looks right, send the one-line go-ahead at the bottom.
This file replaces STITCH-PROMPTS.md. All 3 open items are decided inside it:
accent = mint, one severity set, web-only + finds-only copy.

---

```
RESET: Discard everything from before — all previous screens, prompts, themes, colors
and styles. Start from a blank canvas. Nothing earlier applies.

PRODUCT: WebScanX is a local web vulnerability scanner. The user downloads it, it runs
entirely on their own machine, they point it at a website they are AUTHORIZED to test,
it finds web vulnerabilities, explains each one in plain language (what it is, how to
check it yourself, how to fix it) and exports one report. v1 FINDS and EXPLAINS only —
it never fixes anything automatically. Scope is WEB ONLY (no code scanning, no
dependency scanning). Selling point: everything stays on the device, nothing is uploaded.

YOU WILL DESIGN TWO SURFACES, IN THIS ORDER:
PHASE 1 — THE SHOP (public marketing + download website). Build this now.
PHASE 2 — THE DASHBOARD (the tool's own local interface at localhost:8080). Do NOT start
it until I say "Shop approved". Both phases use the exact same design system.

=== DESIGN SYSTEM (both phases, never deviate) ===
Dark theme only.
Colors: background #0D0C0C; surface #151414; raised surface #1C1B1B; borders and
dividers #2A2828 at 1px; primary text #F2F0EF; secondary text #9A9695; muted #605D5D.
ONE accent: mint #22D3A6 — used ONLY on primary buttons, active nav/tab, focus rings,
progress bar and scan line. Nowhere else. Text on accent buttons is #0D0C0C.
Severity (always color + text label, never color alone, uppercase mono label):
  CRITICAL #FF3B30 — SOLID filled pill, dark #0D0C0C text
  HIGH     #EF4444 — tinted pill (12% background of the color), #EF4444 text
  MEDIUM   #F97316 — tinted pill, #F97316 text
  LOW      #EAB308 — tinted pill, #EAB308 text
  INFO     #8A8A8A — tinted pill, #8A8A8A text
No other red, orange or yellow anywhere in the UI.
Type: headings and UI text in "Space Grotesk" (bold, tight tracking on headings).
ALL technical text — URLs, targets, paths, payloads, code, commands, counts, timestamps,
versions, checksums, file sizes — in "JetBrains Mono".
Sizes: marketing body 16-18px, hero headline 80px; dashboard body 14px, table 13px.
Shape: corner radius 0-2px max. No pill-shaped buttons (severity pills are small
rectangles). No drop shadows, no glassmorphism, no gradients on UI chrome, no glow.
Hierarchy through 1px rules, spacing and font weight. 8px spacing grid, 12-column layout.
Icons: thin 1.5px line icons (Lucide style), used sparingly.
Mood: precise, calm, professional security tool. NO hacker-movie clichés: no matrix
rain, no skulls, no hooded figures, no padlock or shield clip-art, no stock photos.
Copy rules: never say "fix automatically", "auto-fix", "cloud", "AI-powered",
"code scanning" or "dependencies". Never show a "Fixed" status anywhere.

=== PHASE 1 — THE SHOP (one long scrolling landing page, 1440px wide) ===
Flashy only in the hero; calm and quiet from section 6 down.

1. NAV (fixed, transparent over hero): "WebScanX" mono wordmark left; links How it
works, What it checks, Sample report, Docs, GitHub; accent button "Download" right.

2. HERO (full viewport height, centered): mono eyebrow "OPEN-SOURCE · RUNS LOCALLY";
headline "Find your vulnerabilities before they do."; subtext "A local security scanner
that finds and explains web vulnerabilities in plain language. Everything stays on your
device."; accent button "Download for Windows" with small mono "v1.0 · 24 MB", outlined
button "View docs"; below them a 1px bordered badge "● Runs 100% on your machine.
Nothing is uploaded." At the bottom edge, a large perspective-tilted screenshot of the
Dashboard Results screen (findings table with severity pills + detail panel) rising into
view. Faint 1px grid lines in the background fading toward the edges.

3. WHAT IT DOES: one large centered sentence (40px, key words primary, rest secondary):
"WebScanX finds web vulnerabilities, explains them like a colleague would, and never
sends a byte off your machine." Under it a full-width marquee strip between two 1px
rules, mono uppercase: SECURITY HEADERS · TLS · XSS · SQL INJECTION · CSRF · COOKIES ·
CORS · CSP · OPEN REDIRECTS.

4. HOW IT WORKS: eyebrow "HOW IT WORKS", heading "Three steps. No account. No cloud."
Three columns split by 1px vertical rules, each with big mono number, title, 2-line
description and a small UI fragment:
01 Download — terminal line "$ webscanx start"
02 Point at your target — mini URL input + ticked checkbox "I am authorized to scan
   this target"
03 Get a clear report — mini stack of 3 rows with HIGH / MEDIUM / LOW pills.

5. WHAT IT CHECKS: eyebrow "WHAT IT CHECKS", heading "Five modules. Every finding
explained." Bento grid: one large card (2 columns) for XSS, four cards for Security
headers, TLS / certificates, SQL injection, CSRF. Each card: line icon, name, one plain
sentence, mono footer with 2-3 example checks (e.g. "reflected · stored · DOM").
Surface #151414, 1px border, border turns accent on hover (show one hovered).

6. SAMPLE REPORT (the trust-builder): eyebrow "SAMPLE REPORT", heading "This is exactly
what you get.", subtext "A real scan of our own demo target. Nothing staged." A large
framed view of the Dashboard Results screen exactly as specified in Phase 2 section D
(severity summary bar, filter tabs, findings table, open detail panel for "Reflected XSS
in ?q parameter"). Below: text links "Download sample PDF" · "View sample JSON".

7. WHY TRUST IT (calm, no imagery): eyebrow "WHY TRUST IT", heading "Built so you don't
have to trust us." 2x2 grid split by 1px rules, each cell mono label + short heading +
2 sentences:
LOCAL-FIRST — Runs on localhost. No telemetry, no account, works offline.
OPEN-SOURCE — Every check is readable on GitHub. Audit it yourself.
EATS ITS OWN COOKING — We scan WebScanX with WebScanX before every release.
AUTHORIZATION-GATED — It won't start until you confirm you're allowed to test the target.

8. DOWNLOAD: heading "Download WebScanX v1.0". Three platform cards: Windows (.exe),
macOS (.dmg, Apple Silicon + Intel), Linux (.AppImage). Each: platform, mono file size,
accent "Download" button, collapsible mono "SHA-256" checksum row with copy icon. Below:
mono code block "pip install webscanx" with copy button; links Release notes · Verify
signature · System requirements.

9. FAQ (accordion, one item open): Does anything get uploaded? / Is it legal to scan a
site? / Does it fix vulnerabilities? (open, answer: "No. v1 finds and explains each
issue and shows you how to fix it yourself. It never changes your site.") / What does it
need to run? / Is it free?

10. FOOTER: 1px top rule; mono wordmark + tagline "Local web vulnerability scanner."
left; columns Product (Download, Docs, Sample report, Changelog), Project (GitHub,
Security policy, License), Legal (Responsible use, Privacy). Bottom mono small line
"© 2026 WebScanX · Runs locally."

STOP after Phase 1 and wait.

=== PHASE 2 — THE DASHBOARD (only after I say "Shop approved") ===
Desktop web app, 1440x900 per screen. Clarity over flash, almost no motion, dense and
table-driven. Every screen uses the same app shell.

A. APP SHELL: fixed left sidebar 240px. Top: "WebScanX" mono wordmark + tag
"LOCAL · v1.0". Nav with line icons: New Scan, Results, History, Settings (active item:
accent 2px left bar + primary text). Bottom: status chip "● Offline-safe — nothing
leaves this device" and mono "localhost:8080".

B. NEW SCAN: title "New Scan". Centered form column max 640px:
1. "Target" label + large mono input, placeholder "https://staging.example.com".
2. Scan depth segmented control: Quick (~2 min) / Standard (~10 min) / Deep (~45 min),
   each with one line on what it adds.
3. Modules checklist, all checked: Security headers, TLS / certificates, XSS,
   SQL injection, CSRF.
4. AUTHORIZATION GATE — visually prominent 1px bordered box: checkbox "I am authorized to
   scan this target" + secondary text "Scanning systems you don't own or have written
   permission to test may be illegal."
5. Full-width accent button "Start Scan", shown DISABLED (dimmed) because the box is
   unchecked.
Right of the form: narrow muted "Recent targets" list with 3 mono URLs.
Also make a second variant of this screen: checkbox ticked, Start Scan enabled.

C. SCANNING: top row — mono target URL, depth tag "STANDARD", mono elapsed "04:12",
outlined "Stop scan" button. Thin full-width accent progress bar at 62% with mono text
"Checking: XSS — reflected parameters (38 / 61 requests)". Module states: Security
headers ✓ done, TLS ✓ done, XSS ◐ running (accent), SQL injection ○ queued, CSRF ○
queued. Row of 5 live counters with pills: CRITICAL 0, HIGH 2, MEDIUM 3, LOW 5, INFO 8.
"Live findings" feed, newest on top: pill, finding name, mono path, mono timestamp.
Collapsible "Raw log" panel at the bottom, terminal style, mono 12px, dim text.
Also a variant: "Scan complete" state with accent "View results" button.

D. RESULTS (most important — the Shop's Sample Report must match this exactly):
Split: findings table left 60%, detail panel right 40%.
Header: mono target URL, scan date, duration; a single horizontal stacked severity bar
labeled "2 High · 3 Medium · 5 Low · 8 Info"; right side small outlined buttons
"Export report".
Filter row: tabs All (18) / Critical / High / Medium / Low / Info, search input,
"Module" dropdown.
Table (40px rows) columns: Severity (pill), Finding, Location (mono path), Module,
Status (New / Seen / Ignored). 10 realistic rows, e.g. "Missing Content-Security-Policy
header", "Reflected XSS in ?q parameter", "TLS 1.0 enabled", "Cookie without Secure
flag", "SQL error message disclosed", "Missing CSRF token on /account/email".
Row 2 selected (accent left border).
Detail panel for "Reflected XSS in ?q parameter", HIGH pill, with small uppercase mono
section headings:
WHAT IT IS — 2 plain-language sentences.
HOW TO CHECK IT YOURSELF — numbered steps + copyable mono code block with a curl command.
EVIDENCE — mono block with the request and the reflected payload highlighted.
HOW TO FIX IT — plain steps + short code snippet.
REFERENCES — OWASP link, CWE-79.
Also a variant: empty state for a filter with no results.

E. HISTORY: title "History", muted note "Stored locally in ~/.webscanx/scans". Search
input + secondary "Compare two scans" button. Table of 8 past scans: Date, Target
(mono), Depth, Duration, Findings (mini stacked severity bar + counts), actions (Open,
Export, Delete icon).

F. EXPORT REPORT (modal over the dimmed Results screen): title "Export report". Format
cards: PDF "Share with a client", Markdown "Paste into a ticket", HTML "Open in any
browser", JSON "Feed into other tools". Toggles: Include evidence, Include ignored
findings, Redact target hostname. Mono output path
"~/Documents/webscanx-report-2026-09-14.pdf" + "Change". Buttons: "Cancel" (text) and
"Export" (accent).

G. SETTINGS: sections with 1px rules — Default scan depth, Default modules, Report
folder (mono path + Change), Request rate limit (mono number input), Theme note "Dark
only". Accent "Save" button.

QUALITY CHECK every screen before showing it — redo it if:
- any severity color appears without its text label
- accent mint appears anywhere besides buttons / active states / progress / focus
- Start Scan looks clickable while the authorization box is unchecked
- there are shadows, gradients, glow, rounded pills, stock security imagery
- any copy mentions auto-fix, cloud, AI, code or dependency scanning, or "Fixed"
- the Shop's sample report differs from the Dashboard Results screen
```

---

**Go-ahead line (send after the Shop is good):**
```
Shop approved. Now build Phase 2 — the Dashboard, screens A to G, same design system.
```

**Engine chat:** the report must use the same severity hex above (Critical solid
#FF3B30, High #EF4444, Medium #F97316, Low #EAB308, Info #8A8A8A) and drop the
"Fixed" badge for v1.
