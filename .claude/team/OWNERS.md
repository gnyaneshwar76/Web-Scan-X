# WebScanX team ownership (every file has exactly one owner)

| Agent | Owns |
|---|---|
| manager | .claude/ (this file, agents/, team/), edits no code |
| api | webscanx/server.py, cli.py, __main__.py, __init__.py, webscanx/core/*, webscanx/scanners/web/http.py |
| detect | webscanx/scanners/web/* (except http.py), webscanx/scanners/code/*, webscanx/scanners/__init__.py |
| report | webscanx/report/* |
| ui | site/ (all, incl. site/src/imports) |
| pack | pyproject.toml (new), README.md, .gitignore, root docs. NOT web/, design-preview/, index.html, STITCH-*, DESIGN*.md (owner has not approved moving them) |
| test | tests/*, tools/demo_target.py, .github/ (new) |

## Rules for every agent
- Touch only files you own. Need a change elsewhere? Write the exact request under NEEDS in your report.
- Python stdlib only. Keep: safe by default, authorization gate, loopback-only API, finds-only.
- UI: dark only, mint accent, severity always colour + label.
- No git commit/push, no deleting files, no writing scan history to disk.
- Work small and cheap: read only what you need.
- Final reply = report, max 15 lines: CHANGED (files) / DONE (per fix) / SKIPPED / NEEDS / TESTS (ran? result).

## Added 10 Oct 2026 (13 agents). The new ones are read-only until the owner says "draft".
| Agent | Owns |
|---|---|
| reviewer | nothing (read-only code review) |
| verify | nothing (runs checks, scratchpad only) |
| security | SECURITY.md, docs/security/ |
| laws | docs/legal/ |
| policy | docs/policy/ |
| privacy | PRIVACY.md, docs/privacy/ |
