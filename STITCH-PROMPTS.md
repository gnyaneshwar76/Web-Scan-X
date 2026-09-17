> HISTORICAL — superseded by the Figma Make design in `site/`. Kept for reference only.
> Current design handoff: DESIGN-BRIEF.md

# WebScanX — Stitch Prompts

Paste these into Stitch (stitch.withgoogle.com) in order. Paste **one prompt per screen**,
iterate with the follow-ups, then export to Figma and finish there. Don't ship raw
Stitch output.

---

## 0. Setup (do this once)

1. Sign in to Stitch, then **New project**, then pick **Web** (desktop, not mobile).
2. Name the project `WebScanX`.
3. Open **Design system / Theme** and paste the **DESIGN SYSTEM** block below. If your
   Stitch version has no theme panel, paste the block at the top of every prompt instead.
4. Build the **Dashboard first** (sections 1–5). Stitch is best at app screens. Then do
   the Shop (sections 6–13).
5. After each screen, check it against the **Reject if** line. Fix it with a follow-up
   prompt instead of starting over.

### Accent decision (made here, change it in one place)
The accent is **mint `#22D3A6`**, not red. Red is already the Critical/High severity color,
so a red button would look like an alarm. Mint doesn't clash with any severity color and
reads as "terminal / all clear". To swap it, replace `#22D3A6` everywhere in this file.

---

## DESIGN SYSTEM (paste into the theme, or on top of every prompt)

```
WebScanX design system. Dark theme only.
Colors: background #0D0C0C; surface #151414; raised surface #1C1B1B; borders/dividers
#2A2828 at 1-2px; primary text #F2F0EF; secondary text #9A9695; single accent #22D3A6
(mint) used ONLY for primary buttons, active nav/tab, focus rings, progress/scan line.
Severity colors (always paired with a text label, never color alone): Critical #FF3B30,
High #EF4444, Medium #F97316, Low #EAB308, Info #8A8A8A. Severity pills: 12% tinted
background of the color, solid color text, uppercase mono label.
Typography: headings and UI in "Inter Tight" or "Space Grotesk" (bold, tight tracking);
all technical text (URLs, targets, paths, payloads, code, counts, timestamps, IDs) in
"JetBrains Mono". Body 14px in dashboard, 16-18px on marketing site.
Shape: radius 0-4px maximum, no pill-shaped buttons, no drop shadows, no glassmorphism,
no gradients on UI chrome. Hierarchy through thin 1-2px rules, spacing, and type weight.
Spacing on an 8px grid. Icons: thin 1.5px line icons (Lucide style).
Mood: precise, calm, professional security tool. Not "hacker movie", no matrix rain,
no skulls, no padlock clip-art, no neon glow everywhere.
```

---

# PART A — THE DASHBOARD (local tool, `localhost`)

Motion: almost none. Clarity over flash. Dense, table-driven.

## 1. App shell + New Scan

```
Desktop web app, 1440x900, for WebScanX, a local security scanner that runs on the
user's own machine. Use the WebScanX design system.
Layout: fixed left sidebar 240px wide. Top of sidebar: "WebScanX" wordmark in mono with
a small tag "LOCAL · v1.0". Nav items with line icons: New Scan (active, accent left
bar), Results, History, Settings. Bottom of sidebar: a status chip "● Offline-safe —
nothing leaves this device" and the local address "localhost:8080" in mono.
Main area title "New Scan". A single centered form column, max 640px:
1. "Target" label + large mono text input, placeholder "https://staging.example.com".
2. Scan depth: a 3-option segmented control — Quick (~2 min), Standard (~10 min),
   Deep (~45 min) — each with a one-line description of what it adds.
3. Modules: a compact checklist with 5 items, all checked by default: Security headers,
   TLS / certificates, XSS, SQL injection, CSRF.
4. Authorization gate: a bordered box with a checkbox "I am authorized to scan this
   target" and small secondary text "Scanning systems you don't own or have written
   permission to test may be illegal." This box is visually important, not hidden.
5. Full-width primary button "Start Scan" in accent. It is DISABLED (dimmed) until the
   authorization box is checked — show the disabled state.
Right of the form, a narrow muted "Recent targets" list with 3 mono URLs.
```
**Follow-ups:** `Show the enabled state with the checkbox ticked.` ·
`Add an inline validation error under Target: "Enter a full URL including https://".`
**Reject if:** the authorization checkbox is small or buried, or Start looks clickable
while unchecked.

## 2. Scanning (live progress)

```
Same WebScanX app shell and sidebar (Results nav active not needed; keep New Scan
active). Main area: live scan in progress.
Top: target URL in mono, depth badge "STANDARD", elapsed time "04:12" in mono, and a
secondary "Stop scan" button (outlined, not accent).
Below: a thin full-width progress bar in accent at 62%, with text "Checking: XSS —
reflected parameters (38 / 61 requests)" in mono.
Middle row: a module checklist showing states — Security headers ✓ done, TLS ✓ done,
XSS ◐ running (accent), SQL injection ○ queued, CSRF ○ queued.
Row of 5 live counters with severity pills: Critical 0, High 2, Medium 3, Low 5, Info 8.
Bottom half: "Live findings" feed, newest on top, each row: severity pill, finding name,
mono path, timestamp. New rows appear at the top. A small collapsible "Raw log" panel
styled like a terminal (mono, 12px, dim text) at the very bottom.
```
**Follow-ups:** `Show the "Scan complete" end state with a "View results" accent button.`
**Reject if:** it looks like a marketing animation, not a working tool.

## 3. Results (the most important screen — it is reused on the Shop)

```
Same WebScanX app shell, Results nav active. Main area split: findings table left
(~60%), detail panel right (~40%).
Header: target URL in mono, scan date, duration, and a severity summary bar — a single
horizontal stacked bar split by severity counts, with labels "2 High · 3 Medium · 5 Low
· 8 Info". Right side of header: export buttons "PDF", "Markdown", "HTML", "JSON"
(outlined, small).
Filter row: segmented tabs All (18) / Critical / High / Medium / Low / Info, plus a
search input and a "Module" dropdown.
Findings table columns: Severity (pill), Finding, Location (mono path), Module, Status
(New / Seen). 10 realistic rows, e.g. "Missing Content-Security-Policy header",
"Reflected XSS in ?q parameter", "TLS 1.0 enabled", "Cookie without Secure flag",
"SQL error message disclosed", "Missing CSRF token on /account/email". Row 2 is
selected (accent left border).
Detail panel for the selected finding "Reflected XSS in ?q parameter", HIGH:
sections with small uppercase mono headings —
WHAT IT IS (2 plain-language sentences),
HOW TO CHECK IT YOURSELF (numbered steps + a copyable mono code block with a curl
command),
EVIDENCE (mono block showing request and the reflected payload highlighted),
HOW TO FIX (plain steps + a short code snippet),
REFERENCES (OWASP link, CWE-79).
```
**Follow-ups:** `Show the empty state for a filter with no results.` ·
`Make the table denser: 40px rows.`
**Reject if:** severity is shown by color alone with no label, or the detail panel reads
like jargon.

## 4. History

```
Same WebScanX app shell, History nav active. Title "History" with a note in muted text:
"Stored locally in ~/.webscanx/scans".
A table of past scans: Date, Target (mono), Depth, Duration, Findings (mini inline
severity stacked bar + counts), actions (Open, Export, Delete icon). 8 rows.
Above table: search input and a "Compare two scans" secondary button.
Empty-state variant not needed now.
```

## 5. Report export (modal)

```
Same WebScanX app, Results screen dimmed behind a centered modal "Export report".
Format options as selectable cards: PDF, Markdown, HTML, JSON — each with a one-line
use ("Share with a client", "Paste into a ticket", ...). Options: include evidence
(toggle), include fixed/ignored findings (toggle), redact target hostname (toggle).
Output path in mono "~/Documents/webscanx-report-2026-09-14.pdf" with "Change".
Buttons: "Cancel" (text) and "Export" (accent).
```

---

# PART B — THE SHOP (public marketing/download site)

Borrow **structure and motion** from the two reference sites. Never copy their color or
wording:

| Borrow from | What to take | What NOT to take |
|---|---|---|
| **getlayers.ai** | Centered cinematic hero, big poster images with parallax, numbered step lists, stagger-reveal card grids, FAQ accordion, calm multi-column footer | Template-marketplace grids of 8 cards, "unlimited access" upsell tone |
| **scrolltide.co** | Split hero with 2 CTAs, the **tech marquee** (use it for "what it checks"), filterable card tabs, a 3-column "Copy, paste, launch" style workflow row | Pricing/"Go Unlimited" pressure, huge 79-card library wall, countdown urgency |

Motion rule: **flashy in the hero, quiet from "Why trust us" down.** In Stitch these
screens are static. Write motion notes into Figma as annotations.

Tip: generate the Shop as **one long page** ("a single scrolling landing page with these
sections…") first. If Stitch squashes sections, generate it section by section with the
prompts below.

## 6. Nav + Hero

```
Desktop marketing landing page, 1440 wide, for WebScanX, a local web vulnerability
scanner. Use the WebScanX design system (marketing sizes).
Fixed top nav, transparent over hero: "WebScanX" mono wordmark left; links How it works,
What it checks, Sample report, Docs, GitHub; right: accent button "Download".
Hero, full viewport height, centered composition: small mono eyebrow "OPEN-SOURCE ·
RUNS LOCALLY"; huge bold headline (72-88px, tight tracking) "Find your vulnerabilities
before they do."; subtext (18px, secondary) "A local security scanner that finds and
explains web vulnerabilities in plain language. Everything stays on your device.";
two buttons: accent "Download for Windows" (with small mono "v1.0 · 24 MB") and outlined
"View docs". Under buttons a bordered badge "● Runs 100% on your machine. Nothing is
uploaded."
Below the fold edge, a large tilted/perspective screenshot of the dashboard Results
screen (dark app UI with severity pills) emerging from the bottom, like a cinematic
product reveal. Faint 1px grid lines in the background fading out toward edges.
```
**Figma motion note:** headline words rise in with a stagger. On scroll the dashboard
screenshot un-tilts to flat (getlayers-style parallax). A single accent scan line sweeps
the screenshot once.

## 7. What it does + tech marquee

```
Section below the hero, WebScanX system. A single large centered sentence (40px,
mixed weights, key words in primary, the rest in secondary text): "WebScanX finds
vulnerabilities, explains them like a colleague would, and never sends a byte off
your machine."
Under it a full-width horizontal marquee strip between two 1px rules, mono uppercase
items separated by "·": SECURITY HEADERS · TLS · XSS · SQL INJECTION · CSRF · COOKIES ·
CORS · CSP · OPEN REDIRECTS.
```
**Figma motion note:** the marquee scrolls slowly and continuously (like scrolltide's tech
stack strip) and pauses on hover.

## 8. How it works — 3 steps

```
WebScanX system. Section eyebrow mono "HOW IT WORKS", heading "Three steps. No account.
No cloud." Three columns separated by 1px vertical rules, each: large mono number
"01 / 02 / 03", title, 2-line description, and a small UI fragment below:
01 Download — a terminal line "$ webscanx start" in mono.
02 Point at your target — a mini target input with the checked "I am authorized"
   checkbox.
03 Get a clear report — a mini stack of 3 severity pill rows.
```

## 9. What it checks — module cards

```
WebScanX system. Eyebrow "WHAT IT CHECKS", heading "Five modules. Every finding
explained." A bento grid: one large card (spans 2 columns) for "XSS" and four standard
cards for Security headers, TLS / certificates, SQL injection, CSRF. Each card: line
icon, module name, one-sentence plain explanation, and a mono footer listing 2-3
example checks (e.g. "reflected · stored · DOM"). Cards: surface #151414, 1px border,
no radius, border turns accent on hover (show one hovered).
```

## 10. Sample report preview (the trust-builder)

```
WebScanX system. Eyebrow "SAMPLE REPORT", heading "This is exactly what you get."
Subtext "A real scan of our own demo target. Nothing staged."
A large framed product view that reproduces the dashboard Results screen: severity
summary bar, filter tabs, findings table with severity pills, and an open detail panel
for "Reflected XSS in ?q parameter" showing WHAT IT IS / HOW TO CHECK / EVIDENCE / HOW
TO FIX. Below: text links "Download sample PDF" and "View sample JSON".
```
**Important:** don't let Stitch invent a new layout here. In Figma, **replace this with a
component instance of the real Results screen** (section 3). Design it once, use it in
both places.

## 11. Why trust us (calm)

```
WebScanX system, calm and restrained, no imagery, no motion cues. Eyebrow "WHY TRUST
IT", heading "Built so you don't have to trust us." A 2x2 grid separated by 1px rules,
each cell: mono label + short heading + 2 sentences:
LOCAL-FIRST — Runs on localhost. No telemetry, no account, works offline.
OPEN-SOURCE — Every check is readable on GitHub. Audit it yourself.
EATS ITS OWN COOKING — We scan WebScanX with WebScanX before every release.
AUTHORIZATION-GATED — It won't start without you confirming you're allowed to test
the target.
```
**Reject if:** there are glowing shields, padlocks, or stock "security" imagery.

## 12. Download

```
WebScanX system. Heading "Download WebScanX v1.0". Three platform cards in a row:
Windows (.exe), macOS (.dmg, Apple Silicon + Intel), Linux (.AppImage / pip install
webscanx). Each card: platform name, file size, accent "Download" button, and a
collapsible "SHA-256" mono checksum row with a copy icon. Below: a mono code block
"pip install webscanx" with copy button, and links "Release notes", "Verify signature",
"System requirements".
```

## 13. FAQ + Footer

```
WebScanX system. FAQ accordion (getlayers-style, calm): "Does anything get uploaded?",
"Is it legal to scan a site?", "Does it fix vulnerabilities?" (answer: v1 finds and
explains, it does not auto-fix), "What does it need to run?", "Is it free?". One item
open.
Footer: 1px top rule, WebScanX mono wordmark + one-line tagline left; link columns
Product (Download, Docs, Sample report, Changelog), Project (GitHub, Security policy,
License), Legal (Responsible use, Privacy). Bottom row mono small "© 2026 WebScanX ·
Runs locally."
```

---

## Universal follow-up prompts (use on any screen)

- `Reduce visual noise: remove shadows and gradients, use 1px borders instead.`
- `Use JetBrains Mono for every URL, path, number and code value.`
- `Accent #22D3A6 only on the primary button and active state — remove it everywhere else.`
- `Every severity color must have a text label next to it.`
- `Tighten spacing to an 8px grid and align everything to a 12-column layout.`
- `Make this look less AI-generated: fewer decorative icons, more real data.`

## Stitch → Figma

1. On each finished screen, open **Export** and choose **Copy to Figma**, then paste into a Figma
   page. Use page names `Dashboard` and `Shop`.
2. In Figma, turn the colors into **variables** first (bg, surface, border, text, accent,
   5 severities). Stitch output uses raw hex and won't stay consistent otherwise.
3. Rebuild these as components: severity pill, button (primary/outline/disabled), input,
   table row, sidebar nav item, finding detail panel.
4. Make the Results screen a component. The Shop's Sample Report section becomes an
   instance of it.
5. Add motion annotations (sections 6, 7) as sticky notes next to the frames.
6. When done, send me the Figma link. I'll review it and write the per-screen spec with
   exact spacing and hex values.
