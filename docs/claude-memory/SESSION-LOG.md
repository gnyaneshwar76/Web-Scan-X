# WebScanX — session log (recent chats)

A short chronological record of what recent chats did and decided, so a new chat can
continue. For full project state see `webscanx-project-state.md`; to restore after the
reset see `RESTORE.md`; for scan proofs see `../../WEB-TEST-LOG.md`.

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
