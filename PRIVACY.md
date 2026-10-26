> DRAFT - must be reviewed by a qualified lawyer before publication.

# WebScanX Privacy Notice

Last checked against the code: 26 October 2026 (version 0.1.0.dev0).

## In short
WebScanX runs on your own computer. The people who make WebScanX do not receive your scans, targets, findings or reports. WebScanX has no accounts, no telemetry and no analytics.

## What data WebScanX handles
When you run a scan, WebScanX processes data on your machine:
- **Target URLs or folder paths** you enter.
- **Responses from the target**: headers, page bodies, forms, cookies (including `Set-Cookie` values), and TLS certificate details.
- **Anything sensitive the target exposes**: a finding can quote evidence that contains secrets, tokens, cookies or personal data that the target leaked. If you scan a code folder, evidence can contain snippets of your source files.
- **Scan results**: findings, severity, and the report built from them.

## Where it stays
- The only outgoing network traffic from the scanner is to the target you authorise (and to the sites it links to or redirects to, subject to the private-address block described in SECURITY.md). It sends a `User-Agent` of `WebScanX/0.1 (+authorised security testing)`.
- The local engine listens on `127.0.0.1` only; it refuses to start on any other address.
- The scan history lives in the engine's memory only (the last 20 finished scans). It is never written to disk and disappears when you stop the engine.
- Reports are written only where you save them: the CLI writes `report.*` (or the `-o` name you give) to the folder you run it in, and the web dashboard hands you a normal browser download.
- The dashboard keeps small preferences in your browser (`localStorage`: scan depth, enabled modules, rate limit) and the id of the current scan (`sessionStorage`). No scan results are stored there.
- The dashboard loads no external fonts, CDNs, scripts or analytics. It uses system fonts only.

## What is never sent anywhere
WebScanX does not send target URLs, responses, findings, reports, cookies, secrets or your IP address to its authors or to any third party. There is no crash reporting, update check or telemetry in the code.

## Redaction
Reports can mask sensitive values: hosts, query values, values after `Authorization`, `Cookie`, `Set-Cookie`, `password`, `token`, `secret`, `api key`, and long mixed letter-digit tokens. In the dashboard's Export dialog, "Redact" is on by default. In the CLI it is off unless you pass `--redact`. Redaction is pattern-based and may miss some values; review a report before you share it.

## The public GitHub repository and website
- The source code is hosted on GitHub. GitHub processes its own logs (such as IP addresses of visitors) under its own privacy statement. WebScanX adds no analytics, cookies or trackers of its own.
- If you open issues or pull requests, what you write there is public and handled by GitHub.
- If you email the contact below, we use your email and message only to reply.
- [Owner to confirm: where the public website is hosted and what that host logs.]

## Your data about other people
If you scan a system, the results may include personal data of that system's users. You are responsible for having authority to test it and for handling those results lawfully (see the terms in docs/policy/).

## How to delete your data
- Stop the engine (Ctrl-C): all scan history in memory is gone.
- Delete the report files you saved (`report.*` or your `-o` name, and any browser downloads).
- Clear the site's browser storage (browser settings, site data for `127.0.0.1`) to remove saved preferences.
- We hold no copy, so there is nothing to ask us to delete.

## Legal basis and your rights (GDPR, India DPDP Act 2023, CCPA/CPRA)
Because WebScanX does not collect or transmit personal data to its authors, they act neither as a processor nor, for scan data, as a controller; you control all data on your machine. The only data we may receive is an email you send us. You may ask us what we hold, to correct it or delete it, and to stop using it, by emailing the contact below. We do not sell or share personal information. EU/UK residents may complain to their data-protection authority; Indian residents may use the Data Protection Board route under the DPDP Act. [Lawyer: confirm roles, any controller status for the contact email and website host, and whether further notices are required.]

## Children
WebScanX is not directed at children.

## Changes
Changes are published in this file in the repository, with the date above updated.

## Contact
[CONTACT EMAIL - owner to fill]
