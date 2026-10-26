# Plan: scan Android, iOS, Windows, Mac apps and more source languages

Owner request (24 Oct 2026): scan .apk/.aab, .ipa, .exe/.msi, .app/.dmg/.pkg, and web/source types (.html .css .js .php .py .jsp). This reverses the old rule "web + code only". Built in phases; each phase ends with the Manager's check and a log entry. Nothing ships in the Shop copy until it exists.

## Ground rules (defaults, owner may change)
- **Static analysis only.** The target file is never executed or installed. No malware detection, no runtime testing.
- **Stdlib only** (zipfile, plistlib, struct, zlib, re). Depth is below MobSF-class tools; reports must say what was and was not checked.
- **Hostile input:** every parser caps size, entries, depth and decompressed bytes (zip bombs), never extracts outside a temp dir, never trusts offsets. Treated as attack surface; `security` agent reviews each parser.
- **Authorization wording** for files: "I own this file or have the right to analyze it" (`laws` confirms).
- Local only, nothing uploaded. Findings keep the same shape (title, severity, where, what, how to check, evidence, fix, category) so reports, UI and exports work unchanged.

## Phase 0: foundation (api, ui, test)
detect() recognises .apk .aab .ipa .exe .msi .dll .app .dmg .pkg; server/CLI accept a file path (kind mobile/desktop); safe-open helper with the caps above; New Scan screen gets a file-path option; tests with tiny synthetic fixtures.

## Phase 1: more source languages (detect) - cheapest, most value
Rules for PHP (eval, system/exec/shell_exec, include/require of user input, unserialize, string-built SQL, md5/sha1 passwords, display_errors, unrestricted uploads), JSP (Runtime.exec, SQL concatenation, unescaped request output), JS/HTML (innerHTML, eval, document.write, http:// resources, hardcoded keys), CSS (insecure http @import only). On live web scans: flag end-of-life PHP versions from headers (ties to the PHP2Shell news; no CVE database, version list only).

## Phase 2: Android + iOS (new agent `binary`)
- **.apk:** zip + binary AndroidManifest parser. Checks: debuggable, allowBackup, cleartext traffic, exported components without permission, dangerous permissions, old targetSdk, network-security-config, secrets/URLs in resources/dex strings, signing files present.
- **.aab:** zip listing + strings only (manifest is protobuf; full parse is later). Reported as limited.
- **.ipa:** zip + Info.plist via plistlib. Checks: App Transport Security exceptions, URL schemes, missing/odd permission strings, debug provisioning (get-task-allow), secrets/http URLs in the Mach-O, PIE/stack-protector flags.

## Phase 3: Windows (binary)
PE header parser. Checks: ASLR, DEP, high-entropy ASLR, CFG, SafeSEH, Authenticode signature present (presence only; real validation needs Windows tools, optional), strings with secrets/URLs. **.msi** (OLE container): signature presence + strings only; limited.

## Phase 4: macOS (binary)
.app (a folder): Info.plist, ATS, Mach-O flags. .pkg: xar header/TOC via struct+zlib, scripts listed and scanned for risky commands. **.dmg:** cannot be opened with stdlib off macOS; report "extract first" and scan the .app inside. Entitlements/notarization checks only when run on a Mac.

## Who does what
api (phase 0 server/CLI), ui (file option, platform labels), detect (phase 1), binary (new agent: phases 2-4), test (fixtures per phase), reviewer + security (each parser, hostile files), laws (reverse-engineering/licence wording), report (platform field, MASVS references), manager (check after each phase). Work runs in the "WebScanX agent team" section.

## Cost and order
About 3 agent runs per phase plus one review run each: ~20 runs total. One phase at a time, owner sees the Manager's report between phases. Start: phases 0 and 1 together.

## Known limits to say out loud in the product
Static hygiene checks, not a full pentest; .aab/.msi/.dmg limited; no obfuscation unpacking; results can miss issues.

## Added 24 Oct: AI helper phase (after Phase 1, before Android)
- AI never decides what is a vulnerability; the normal checks find problems with proof. AI works after them.
- Step A (first): false-alarm review of each finding + a plain-language summary and "fix these first" ranking.
- Step B (later): AI picks which checks fit the site; AI-assisted crawling of login pages and JavaScript sites.
- Off by default. Local model first (nothing leaves the machine); cloud model only by explicit opt-in, with secrets redacted before sending. Every AI note is labelled "AI suggestion, check it".
- Needs: owner OK to drop the old "never say AI on the Shop" rule; privacy + laws agents update their documents.
