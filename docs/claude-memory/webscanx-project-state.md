---
name: webscanx-project-state
description: "Full WebScanX handoff — what it is, repo, engine (19 scanners) status, architecture, how to run, what's done/not done. Read this first to continue WebScanX in a new chat."
metadata: 
  node_type: memory
  type: project
  originSessionId: a9047ca3-7aeb-4724-af74-7f81569c76bd
  modified: 2026-09-17T20:01:28.324Z
---

# WebScanX — complete project handoff

**LAST VERIFIED (2026-09-18, second pass):** the UI now drives the engine for real.
Added `webscanx/server.py` (loopback API) + `site/src/data/api.ts` (client/store) and
wired New Scan / Scanning / Results / Export / History to live data. Tests green,
tree clean, pushed (commit 09f6fc3). Resume point: PDF export, the auto-fixer,
persisting history to disk, or polish. See "How to run" for the two-process start.

**What it is:** a local security scanner. Point it at a website (or your own code
folder) and it finds vulnerabilities, explains each in plain language (what it is /
how to check / evidence / how to fix), and exports one report. v1 = **finds only**
(no auto-fix). Selling point: 100% local, nothing uploaded.

**Location:** `E:\WebScanX` (a SEPARATE project from RideConnectX, which is `E:\RideConnetX`).
The shell cwd often defaults to `E:\RideConnetX` — always `cd /e/WebScanX` first
or use absolute paths.

**GitHub:** https://github.com/gnyaneshwar76/Web-Scan-X (public, owned by user).
Already git-initialized with remote `origin`, branch `main`, local and remote in sync.
Windows Git Credential Manager has a cached login, so pushing just works:
`cd /e/WebScanX && git add -A && git commit -m "msg" && git push`
Commit attribution line to append: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.

**Two tracks:** the ENGINE (Python backend — DONE) and the WEB/DESIGN (DONE, lives in
`site/`). The design is authored in Figma Make (deployed at
https://rename-slot-39298091.figma.site/), exported as a zip and copied into `site/`
(React + Vite + Tailwind v4): Shop page + dashboard screens (new-scan, scanning, results,
history, settings, export modal), all sharing one findings dataset in
`site/src/data/findings.ts` (a real engine report). Full design handoff:
`E:\WebScanX\DESIGN-BRIEF.md`. Figma component file: KV2plgQwDWEyVa2U4lUqmd (gmail
account, team "Andriod studio"). `web/`, `design-preview/`, root `index.html` and the
STITCH-*/DESIGN.md docs are superseded reference only. See [[webscanx-report-style]] and
[[webscanx-drive-stitch-directly]].

## Engine status: COMPLETE + tested (web + code targets)

**15 web scanners** (`webscanx/scanners/web/`, TargetKind.WEB):
headers, tls, xss (reflected), sqli (error-based), csrf, cors, redirect (open),
disclosure (.git/.env/banners), methods (OPTIONS/TRACE), csp (weak policy),
mixed (content), secrets (leaked keys), errors (stack traces), cookies
(SameSite/prefix), forms (insecure password forms).

**4 code/SAST scanners** (`webscanx/scanners/code/`, TargetKind.CODE):
secrets (hardcoded creds), injection (eval/exec/os.system/shell/pickle/yaml/SQL/JS
sinks), crypto (md5/sha1/DES/ECB/weak RNG), config (debug=True/verify=False/wildcard CORS).

## Architecture (the "spine" — keep stable)
- `core/finding.py` — `Finding` dataclass (title, severity, where, scanner, what,
  how_to_check, evidence, remediation, category, references, fixed, fingerprint).
  `Severity` IntEnum INFO<LOW<MEDIUM<HIGH<CRITICAL. Dedupe by fingerprint.
- `core/target.py` — `detect()` returns TargetKind WEB/CODE/MOBILE/DESKTOP/UNKNOWN.
- `core/engine.py` — `register(kind,name)` decorator; `run(target,ctx)` runs applicable
  scanners, dedupes, sorts worst-first. `ScanContext(aggressive, timeout, only, cache,
  delay, max_pages, max_depth)`. Shared `cache` holds the one crawl/walk.
- `scanners/__init__.py` imports `web` and `code` (import = register). `cli.py` imports
  `scanners`, so registration happens.
- `scanners/web/crawler.py` — one same-origin capped crawl (MAX_PAGES=25, MAX_DEPTH=2),
  `get_sitemap(target,ctx)` memoized in ctx.cache. `scanners/code/walker.py` — source-tree
  walk (skips deps/build/VCS/binary), `get_tree`. `scanners/code/_rules.py` — shared
  regex-rule runner for code scanners.
- `scanners/web/http.py` — the ONLY network client. `fetch(url, method, data, timeout,
  verify_tls, headers, allow_redirects, retries)`; Response.status 0 = transport error.
  Enforces timeout + 3MB cap; retries transient errors; `set_rate(delay)` throttle.
- `report/report.py` — `Report`; `report/render/__init__.py` — 6 formats: json, md, txt,
  csv, sarif, html. PDF registered but raises NotImplementedError (Phase 2). The html
  renderer is the polished one (see [[webscanx-report-style]]).
- `cli.py` — flags: target/--code, -f/--format, -o, --aggressive, --only, --timeout,
  --delay, --max-pages, --depth, -y/--yes, --list-formats, --version. Exit codes:
  0 clean, 1 low/med, 2 high/crit, 3 error. Permission gate before scanning non-code.

## Locked decisions
- Web + code targets only for now; finds-only (no fixer yet).
- Safe by default: only benign marker payloads / reads; `--aggressive` unlocks
  POST-form probing and data-changing tests. Never weaken the permission gate.
- stdlib only (urllib/ssl/html.parser/re/os) — no third-party deps (local-first).
- Category tags use CWE first, OWASP 2025 as context (Top-10 numbering churns).
- Every scanner: registers at import, yields Findings, has an assert-based `demo()`.

## How to run / test
- Tests (no pytest, no network): `cd /e/WebScanX && python tests/test_spine.py`
  — spins a local vulnerable HTTP fixture + temp insecure source dir, asserts all
  scanners fire. All green.
- A scanner's own check: `python -m webscanx.scanners.web.<name>` (prints "<name>: ok").
- UI + engine (the real app): two processes ---
  `cd /e/WebScanX && python -m webscanx.server` (loopback API on 127.0.0.1:8765),
  then `cd site && npx vite preview --port 8443 --host 127.0.0.1` (or `npx vite dev`),
  and open http://127.0.0.1:8443/#/dashboard/new-scan. With no engine running the
  UI falls back to the bundled sample findings and says "sample data".
  `python tools/demo_target.py` serves the vulnerable fixture on :8000 to scan.
- Real scan: `python -m webscanx <url> -f html -f json -o report`
  or `python -m webscanx --code . -y -f html -o report`.
- Sample report generator lives in the session scratchpad (`show.py`): scans the fixture
  and writes `sample_report.html`/`.md` (throwaway, regenerable).

## NOT done (deliberate — don't build without asking)
- Mobile (.apk/.ipa) + desktop-binary scanners — recommended AGAINST (needs heavy
  parsing/deps, breaks stdlib rule, v1 is web-focused).
- PDF export (Phase 2; for now use html + browser print-to-PDF, which the html
  renderer styles cleanly for print).
- The auto-fixer (later phase; only owned CODE would ever be fixable).
- Scan history lives in the engine's memory only -- it dies when the server stops.
  Persisting it to `~/.webscanx/scans` is a deliberate not-yet (it writes to the
  user's disk; ask first).
- The Export modal's three toggles (evidence / ignored / redact) are still no-ops:
  the renderers always emit every finding with evidence.
- The API has no auth beyond loopback + Origin checks; that is fine for a local
  tool, but never bind it to a routable address (the code refuses to).

## Context-handoff protocol (user's standing request)
When context is nearly full: update THIS file with anything new, then tell the user to
start a new chat — MEMORY.md auto-loads and points here, so work continues without loss.
