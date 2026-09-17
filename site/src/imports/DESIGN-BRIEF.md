# WebScanX — Design Brief (the "car" track)

Hand this to a new chat to continue the DESIGN work. The engine (the Python scanner)
is being built separately under `E:\WebScanX\webscanx\` — this file is only about the
two web surfaces. Paste this whole file into the new chat to carry full context.

---

## What WebScanX is (one paragraph)

A local security scanner. A client downloads a tool that runs entirely on their own
machine, points it at a target they're **authorized** to test, and it finds web
vulnerabilities, explains each in plain language (what it is, how to check it, how to
fix it), and produces one report they can export (PDF/MD/HTML/etc.). v1 **finds only**
— no auto-fixing. Main selling point: **everything stays on the device, nothing is ever
uploaded.**

---

## Locked decisions (do NOT re-litigate in the new chat)

- **Model A architecture:** the website is a *shop* (learn / download / docs / trust).
  The scanner is a *downloadable local tool*. They do NOT connect at runtime; the site
  just offers the tool for download. (Not a web app where a server scans — that would
  break "everything local".)
- **The tool's interface = a local web dashboard** (runs on the user's own machine at
  something like `localhost:8080`). Looks like a web app, but 100% local, works offline.
- So there are **TWO web surfaces to design:**
  1. **The Shop** — public marketing/download site.
  2. **The Dashboard** — the tool's local interface.
- **Design is done by the user** (in Figma / Stitch). Claude writes briefs and advises,
  does not design. Claude may view the Figma when asked.
- The old `E:\WebScanX\index.html` (v4 red landing page) is a **throwaway sample** — do
  NOT base the new design on it.
- Inspiration refs (for motion/structure only, NOT copy or color): scrolltide.co,
  getlayers.ai. Borrow how things move and how sections are arranged; keep our own
  identity. Avoid their fake-urgency countdown timers (bad for a trust-based tool).

---

## Shared visual identity (both surfaces obey this)

- **Dark theme** (near-black ground, e.g. `#0d0c0c`).
- **One accent color** used sparingly (buttons, active states, scan line). DECIDED:
  mint `#22D3A6` (red is reserved for Critical/High severity). Severity hex: Critical #FF3B30 solid, High #EF4444, Medium #F97316, Low #EAB308, Info #8A8A8A.
- **Two typefaces:** a strong sans for headings/body, a **monospace** for technical text
  (targets, payloads, code, findings). The mono is what makes it read like a hacker tool.
- **One severity color system, shared on BOTH surfaces** (color + a text label, never
  color alone):
  - Critical / High = red
  - Medium = orange
  - Low = yellow
  - Info = gray
- Zero-radius or minimal-radius, 2px rules as dividers = clean modernist feel (optional
  but matches the sample's language).

---

## Web 1 — The Shop (marketing / download site)

**Job:** convince → build trust → get the download. Flashy hero, calm honest body.

Sections top-to-bottom:
1. **Hero** — one punchy line + big **Download** button + badge "Runs 100% on your
   machine. Nothing leaves your device." (Cinematic motion lives here.)
2. **What it does** — one sentence: finds vulnerabilities, explains them plainly, all local.
3. **How it works — 3 steps:** Download → Point at your target → Get a clear report.
4. **What it checks** — module cards (headers, TLS, XSS, SQLi, CSRF).
5. **Sample report preview** — show the ACTUAL report output. Biggest trust-builder.
6. **Why trust us** — local-first, open-source, passes its own scan, authorization-gated.
   Keep this section CALM, not flashy (trust = calm).
7. **Download** — platform, version, checksums.
8. Docs link + footer.

Note: flash only in the hero; go quiet and confident by the trust section.

---

## Web 2 — The Dashboard (the tool's local interface)

**Job:** a tool used repeatedly. Clarity over beauty, function over flash. Think app,
not landing page. App shell (sidebar or top tabs) + these screens:

1. **New Scan** — target input; a REQUIRED checkbox "I am authorized to scan this
   target" (the ethics gate, made visible); scan depth selector (Quick / Standard /
   Deep); big Start button.
2. **Scanning** — live progress: what it's checking now, findings appearing as found.
3. **Results** — findings list color-coded by severity; filter (All/High/Med/Low);
   click a finding → detail panel: what it is, how to check it yourself, evidence, fix.
4. **Report / History** — export buttons (PDF/MD/JSON/etc.) + a local list of past scans.

Note: use the SAME severity colors as the shop's sample report, so what a client was
shown matches what they get. Denser and calmer than the shop; less motion, more tables.

**Pro tip that ties it together:** make the shop's "sample report" look *identical* to
the real dashboard results view. Design the report view once, use it in both places.

---

## Tools & workflow

### Figma (refine + final, portfolio-recognized)
- Where the design gets polished and made "yours". Industry standard.

### Stitch (Google AI UI tool — fast first drafts, exports to Figma)
Steps: sign in at stitch.withgoogle.com → describe ONE screen per prompt → iterate with
follow-ups → export to Figma → refine there. Best for the **dashboard** (app screens).
Do NOT ship raw Stitch output (looks AI-made) — always finish in Figma.

Ready-to-paste Stitch prompts:

**Shop hero:**
> A landing page hero for a cybersecurity tool called WebScanX. Near-black background
> (#0d0c0c), single red accent (#ec3013), bold sans-serif headline, monospace for
> technical text. Headline: "Find your vulnerabilities before they do." Subtext: "A
> local security scanner that finds and explains web vulnerabilities — everything stays
> on your device." Primary button "Download", secondary "View docs". Small badge: "Runs
> 100% locally. Nothing leaves your device." Cinematic, minimal, premium developer-tool
> aesthetic.

**Dashboard — New Scan:**
> A desktop web dashboard for a local security scanner. Dark theme, near-black
> background, single red accent, monospace for technical values. Left sidebar nav: New
> Scan, Results, History, Settings. Main area "New Scan": a target URL input, a required
> checkbox "I am authorized to scan this target", a scan depth selector (Quick /
> Standard / Deep), and a large "Start Scan" button. Clean, functional, dense,
> professional.

**Dashboard — Results:**
> A security scan results screen, dark theme, single red accent, monospace for paths and
> payloads. A findings table with columns: Severity (color-coded pill — red=high,
> orange=medium, yellow=low), Finding, Location, Category. Filter buttons: All, High,
> Medium, Low. Clicking a row opens a right-side detail panel showing: what the problem
> is, how to check it yourself, evidence, and how to fix it. Export buttons: PDF,
> Markdown, JSON.

Keep the same colors in every prompt so all screens match.

### Search keywords for the inspiration libraries (scrolltide / getlayers)
- Shop: `hero`, `landing page`, `SaaS`, `developer tool`, `CLI`, `terminal`, `code`,
  `dark`, `cinematic`, `gradient`, `feature grid`, `bento`, `download`, `CTA`,
  `how it works`, `steps`, `social proof`, `stats`, `pricing`, `FAQ`, `footer`,
  `security`, `tech`.
- Dashboard: `dashboard`, `admin`, `app UI`, `data table`, `table`, `list`, `analytics`,
  `charts`, `sidebar`, `cards`, `detail panel`, `status`, `monitoring`, `form`,
  `settings`.
- Look & motion: `scroll animation`, `parallax`, `reveal on scroll`, `sticky scroll`,
  `mono`, `monospace`, `glassmorphism`, `glow`, `grid background`, `dark mode`.

Filter tip: borrow **structure and motion**, not color or copy. Keep our own identity.

---

## Where to start (suggested)

1. Pick the ONE accent color.
2. Draft the **dashboard** screens in Stitch (its sweet spot) → export to Figma.
3. Design the **shop** more custom in Figma (needs art direction Stitch won't give).
4. Design the **report view** once; reuse it as the shop's "sample report".
5. When ready, ask Claude for a full per-screen Figma brief with exact spacing + hex.

Engine progress (separate chat) will produce the real report formats + severity colors
to match against — align the dashboard's colors to those when they're finalized.
