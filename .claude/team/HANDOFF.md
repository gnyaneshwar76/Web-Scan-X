# WebScanX agent team: start here (paste this into the new section)

You are the General Manager of the WebScanX agent team. The owner only commands. Agents do the work. The `manager` agent reads all reports and gives ONE final report. Reports go: agent -> manager -> you -> owner.

## The project
WebScanX (E:\WebScanX, repo github.com/gnyaneshwar76/Web-Scan-X): a local web-vulnerability scanner. Python engine in `webscanx/` (stdlib only), React site in `site/`. It is about to be published as a public website that many people will use. Start with `docs/claude-memory/webscanx-project-state.md` and `DESIGN-BRIEF.md`.

## The team (13 agents, all Sonnet, files in `.claude/agents/`, ownership in `.claude/team/OWNERS.md`)
| Agent | Does | Effort |
|---|---|---|
| manager | checks ownership, runs tests, one final report | low |
| api | server.py, cli.py, core/, http.py | high |
| detect | scanners | high |
| report | report/ and PDF | medium |
| ui | site/ | medium |
| pack | pyproject, README | low |
| test | tests/, CI | medium |
| reviewer | read-only code review (code-review skill) | high |
| verify | runs the checks nobody ran yet (127.0.0.1 and scanme.nmap.org only) | medium |
| security | threat model, SECURITY.md | high |
| laws | laws and compliance (not a lawyer: flags what a human lawyer must confirm) | medium |
| policy | Terms, Acceptable Use, Responsible Disclosure | medium |
| privacy | proves the "nothing is uploaded" claim, PRIVACY.md | medium |

Agents cannot start agents. You hand each work order to its agent unchanged and give the manager the reports. Run independent agents in parallel; run dependent ones in order.

## Done so far (uncommitted, nothing pushed)
Per-scan rate limiter; Host/Origin allow-list, 2-scan cap, job eviction; server serves site/dist; robots/sitemap/script-route crawling; boolean SQLi; fewer XSS false positives; report split into one file per format, evidence/ignored/redact options, stdlib PDF; checkCommand filled; Shop claims about pip/downloads/checksums removed; Export toggles wired; pyproject.toml; second test fixture + server/report tests + CI file. Manager check: all tests pass, no ownership violations.

## First jobs for this section
1. Run the read-only REVIEW round with the 6 new agents (reviewer, verify, security, laws, policy, privacy). Each reads the whole project from its point of view, edits nothing, and reports FOUND / MISSING / BETTER / NEEDS. The earlier attempt was stopped on purpose so it would run here.
2. Manager reads the 6 reports and gives the owner one report with a ranked launch checklist.
3. Only after the owner says "draft": security, laws, policy and privacy write their documents. Only after the owner says "fix": owners fix what the reviews found.

## Rules that never change
- Owner's yes first for: commit/push, deleting or moving files (web/, design-preview/, index.html, STITCH-*, DESIGN*.md), saving scan history to disk, `npm install`, any scan of a host that is not 127.0.0.1 or scanme.nmap.org.
- Stdlib only. Safe by default. Authorization gate stays. API loopback only. Finds-only. Dark UI, mint accent, severity colour + label.
- Fixes made only in site/ must be redone in Figma Make: see `site/FIGMA-REDO.md`.
- Keep limit use low: Sonnet everywhere, short reports, no arena runs.

## Open questions for the owner
Archive or delete the clutter; history on disk; strict Host/Origin is on; is `--only` really limiting scanners (verify checks); UI build not yet run (needs `npm install` in site/); CI not yet run on GitHub.

## Agent Office
`http://localhost:4747`. If desks are missing: `sh .claude/team/staff.sh` (desks vanish after 6 hours or a server restart).

Running record: docs/PROJECT-LOG.md. Update it after every response and read it first.

## Current state (26 Oct 2026) - read docs/PROJECT-LOG.md for details
- Team is now 15 agents: the 13 above plus `binary` (app-package scanners) and `ai` (optional AI helper).
- On main and pushed: server hardening, SSRF guard, API token, security headers, report split + PDF + redaction, MIT LICENSE, install steps, DRAFT legal docs.
- Done and pushed: phases 0 and 2-4 (Android/iPhone/Windows/Mac static checks) + AI helper, security-review fixes (60 tests OK). Phase 1 (PHP/JSP code rules) done 27 Oct in code/injection_web.py.
- Owner still to do: fill legal placeholders (contact email, jurisdiction, response days), lawyer review, redo site/FIGMA-REDO.md in Figma Make.
