# Changes to redo in Figma Make

1. Shop landing: removed the platform picker (Windows/macOS/Linux) from the hero.
2. Shop landing hero button: "Download for Windows" -> "Run it locally"; the size note became "Python 3.9+ · stdlib only".
3. Shop landing nav button: "Download" -> "Get started". Footer link "Download" -> "Get started".
4. Step 01: title "Download" -> "Start it"; text -> "Run the local engine from the project folder. Nothing else to install."; command chip -> `python -m webscanx.server`.
5. Download section replaced by "Get started / Run WebScanX locally": one command chip (`python -m webscanx.server`) and "Then open http://127.0.0.1:8765". Removed the three platform cards, SHA-256 checksums, `pip install webscanx`, and the Release notes / Verify signature / System requirements links.
6. FAQ "What does it need to run?": now "Python 3.9+ and nothing else. No browser, no Docker, no database."
7. Dashboard Results: "How to verify" command box is hidden when a finding has no check command (live scans may omit it). "Ignore" now hides the finding and is disabled for sample data (no fingerprint).
8. Export modal: no visual change; the three toggles now drive the export (Include evidence, Include ignored findings, Redact target hostname).
9. Fonts: removed the Google Fonts @import and the static.figma.com @font-face from src/index.css. Body now uses a system sans stack (ui-sans-serif, system-ui, Segoe UI...), mono uses ui-monospace, Cascadia Mono... No woff2 exists in the repo; the owner must add real woff2 files under site/public/fonts and declare them with local @font-face. Reference-only leftovers still hold font URLs: src/imports/index.html and src/imports/pasted_text/webscanx-shop-preview.html (not built).
10. Privacy line (Shop hero, dashboard sidebar footer) now reads: "Scan data stays on this machine; the scanner contacts only the target you authorise." (was "Nothing leaves your device." / "No data leaves this device"). src/imports/ShopLanding1440 and the brief/prompt .md files still carry the old wording.
11. Export modal: Redact toggle now ON by default and labelled "Redact secrets, cookies, tokens and target address" (was "Redact target hostname").
12. History: removed the 8 invented sample scans. Empty state: "No scans saved. Scan history is not stored on disk."; footer shows the real session count.
13. Results: severity filter/badge counts now exclude ignored findings. Ignore set is in memory and resets on reload.
14. NewScan authorization checkbox: label now "I own this target or have written permission to test it, and I accept responsibility." + "Acceptable Use" link (/acceptable-use, page not yet built) + long consent note below (wording pending lawyer review).
15. Shop: Python requirement 3.9+ -> 3.10+ (hero chip and FAQ). Footer Security policy / License / Responsible use / Privacy are dimmed, non-hover, title "Coming soon".
