# WebScanX — restore after a laptop reset

Everything needed to continue is in two places:
- **This GitHub repo** (https://github.com/gnyaneshwar76/Web-Scan-X) — all project code,
  tests, docs, the `site/` frontend, and the WebScanX handoff notes in `docs/claude-memory/`.
- **The `_backup/` folder** inside the E:\WebScanX folder backup (gitignored, local-only) —
  the FULL Claude memory (`_backup/claude-memory/`, all projects incl. RideConnectX) and
  design zips. This is NOT on GitHub by design (keeps private notes out of a public repo).

## Steps to restore
1. Install Claude Code again.
2. Get the project back: either restore the E:\WebScanX folder from your backup, OR
   `git clone https://github.com/gnyaneshwar76/Web-Scan-X.git E:\WebScanX`
   (cloning gives the code but NOT `_backup/`, which is only in your folder backup).
3. Restore Claude's memory so chats continue seamlessly: copy every file from
   `_backup/claude-memory/` into `C:\Users\<you>\.claude\projects\E--RideConnetX\memory\`
   (including `MEMORY.md`). If you only have the GitHub clone, use `docs/claude-memory/`
   instead — that has the WebScanX notes but not the RideConnectX ones.
4. Verify the engine: `cd E:\WebScanX && python tests/test_spine.py` — expect
   "all spine self-checks passed".
5. In a new chat, say "continue WebScanX" — MEMORY.md auto-loads and points to the
   full handoff (`webscanx-project-state.md`).

## What's where (quick map)
- Engine: `webscanx/` (15 web + 4 code scanners). Run: `python -m webscanx --help`.
- Tests: `tests/test_spine.py`.
- Frontend/design: `site/` (React/Vite), `web/`, `design-preview/`, `index.html`, `docs/`.
- Handoff notes: `docs/claude-memory/` (GitHub) and `_backup/claude-memory/` (local, full).
