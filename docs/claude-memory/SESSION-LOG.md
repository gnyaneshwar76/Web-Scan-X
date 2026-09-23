# WebScanX — session log (recent chats)

A short chronological record of what recent chats did and decided, so a new chat can
continue. For full project state see `webscanx-project-state.md`; to restore after the
reset see `RESTORE.md`; for scan proofs see `../../WEB-TEST-LOG.md`.

---

## 14–23 Sep 2026 — the design chat (Stitch → code prototype → Figma → Figma Make)

Full transcript: `E:\WebScanX\_backup\conversations\webscanx-design-chat.md` (plus the
raw zip). Local only — that chat contains a pasted API key, masked in the .md.

**How the design got here**
1. Three open questions settled: accent **mint `#22D3A6`** (red was already the
   High/Critical colour, so a red button read as an alarm); severity fixed at
   Critical `#FF3B30`, High `#EF4444`, Medium `#F97316`, Low `#EAB308`, Info `#8A8A8A`;
   scope confirmed web-only, finds-and-explains-only.
2. Both surfaces drafted in Google Stitch from one master prompt. Output read as
   generated — bordered boxes everywhere, filler jargon, a sample report whose numbers
   contradicted its own table. Kept only as reference (`STITCH-*.md`, `design-preview/`).
3. scrolltide.co and getlayers.ai studied for composition (one cinematic hero, big
   product visuals, space, few borders). Their colours and copy deliberately not copied.
4. A working prototype hand-built in `web/` (plain HTML/CSS/JS) to prove the screens
   actually work: authorization gate, simulated scan, filters, real file exports.
5. Figma component library built (tokens, text styles, Severity Pill, Button, Nav Item,
   Sidebar, Finding Row, Report + both pages). Built first in the college account by
   mistake, then rebuilt in gnyaneshwar76@gmail.com, team "Andriod studio", file
   `KV2plgQwDWEyVa2U4lUqmd`.
6. **Figma Make became the source of truth**, exported into `site/` (React + Vite).
7. Two review rounds on that build. Round one found the serious one: the Shop showed 18
   invented findings while the Dashboard showed the 8 real engine findings, under the
   words "nothing staged". Round two confirmed both surfaces now read one dataset,
   `site/src/data/findings.ts`.
8. Repo cleanup: `site/` committed, README rewritten, stray severity colours in
   `index.css` and the error reds aligned to the locked palette.

**Decisions worth not re-opening**
- Mint for actions, never red. One severity system, always colour **and** text label.
- The Shop's sample report and the Dashboard's Results screen stay the same component on
  the same data — that is the whole trust argument.
- Plain language in copy: no telemetry / thread-pool / "engine" jargon.
- Figma Make authors the design; `site/` ships it. A fix made only in `site/` is undone
  by the next export unless re-applied upstream.

**What burned time (don't repeat)**
- Pasting prompts into Stitch by hand and asking "see once" each round; driving the tool
  through its MCP connection was far faster.
- Building in whichever Figma account the connector was signed into — check `whoami` first.
- Running Figma writes in parallel: page context leaked between calls and a page landed
  on the wrong canvas. Keep Figma writes sequential; attach frames to their page explicitly.

---

## 18–23 Sep 2026 — design↔engine connected, tested, backed up

**What was done**
- Reviewed the `site/` UI on mobile (375px) and fixed the dashboard shell, Results,
  Scanning, History, Settings to stack/scroll properly. Desktop unchanged (`md:`-gated).
- Found and fixed a blocker: `site/.figma/make/site.json` was missing from the Figma
  export, so Vite wouldn't start. Committed it.
- Connected the design to the Python engine over the localhost API (`webscanx/server.py`,
  :8765). The API wiring + `site/src/data/api.ts` were authored in a parallel session;
  this chat verified them end to end and added the test tooling.
- Added `tools/demo_target.py` — serves the test suite's vulnerable fixture as a standing
  scan target on :8000.
- Fixed `History.tsx` to refetch on window focus (so a restarted engine isn't shown stale)
  and "1 scans" -> "1 scan".

**Tested — real, not scripted** (proof in `WEB-TEST-LOG.md`)
- Local demo target (:8000): 24 findings, all 15 modules; changing random XSS markers.
- **scanme.nmap.org** (real internet, scanning permitted): 6 findings; `Apache/2.4.7
  (Ubuntu)` banner matched an independent `curl`. Full pipeline confirmed.
- Could NOT drive a remote scan from inside Claude's own Chrome automation — the safety
  layer blocks entering an external target. The rider ran scanme themselves; that's fine.

**Decisions**
- google.com and any site the rider doesn't own are off-limits (unauthorized scanning).
  Only local targets and owner-permitted hosts (scanme.nmap.org) are used.
- Every web test gets a proof entry in `WEB-TEST-LOG.md` (standing rule).

**Backup (23 Sep, before laptop reset)**
- Committed + pushed everything to GitHub `main`; backup commit `300a229`.
- Full Claude memory copied to `_backup/claude-memory/` (gitignored, local-only) and the
  WebScanX subset to `docs/claude-memory/` (on GitHub). See `RESTORE.md`.

**Still open (next chat)**
1. Scan history is in-memory only — no persistence across engine restarts.
2. PDF export unimplemented (engine 501) — modal falls back to HTML-to-print.
3. `checkCommand` empty on live scans — copy-command UI only shows on sample data.
4. `site/` fixes must be re-applied in Figma Make or the next export undoes them.
5. Shop download buttons are placeholders — no built binary yet.

**Uncommitted at handoff:** none — working tree clean after `300a229` (plus this log).
