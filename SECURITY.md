> DRAFT - must be reviewed by a qualified lawyer before publication.

# Security Policy

## Supported versions
WebScanX is pre-release (0.1.0.dev0). Only the latest commit on `main` is supported; fixes are not backported.

## Reporting a vulnerability
Follow [docs/policy/DISCLOSURE.md](docs/policy/DISCLOSURE.md). Email [CONTACT EMAIL - owner to fill]; please do not open a public issue for a security problem. This policy covers WebScanX itself (scanner, local API, dashboard, site), not problems you find in other sites with it.

## Security model
WebScanX is a local tool: the engine and dashboard run on your machine and use only the Python standard library (no third-party runtime dependencies).

- **Loopback only.** The API binds `127.0.0.1`; `--host` accepts only `127.0.0.1`, `localhost` or `::1`, anything else is refused.
- **Host and Origin checks.** Every request's `Host` must be a loopback name (defence against DNS rebinding) and any `Origin` must be an http(s) loopback origin, or the request gets 403. CORS headers are sent only for allowed origins.
- **Access token.** The engine creates a random token at start (or uses `WEBSCANX_TOKEN`), prints it, and puts it in the page it serves. Every API call except the health check must send it in the `X-WebScanX-Token` header (report downloads may pass `?token=`); wrong or missing tokens get 401.
- **Authorization gate.** A web scan needs `authorized: true` in the API call, or an explicit confirmation (or `-y`) in the CLI.
- **SSRF guard.** The target host is resolved once, every address is checked, and the connection goes to that vetted IP (no second lookup). Private, loopback, link-local and metadata ranges (including IPv4 embedded in IPv6) are refused; redirects are re-checked; proxy environment variables are ignored. The only exception is a loopback target you explicitly scan (such as the demo fixture), and then only that host may be contacted.
- **Safe by default.** Probes are read-only. POST-form probes for XSS and SQL injection run only with `--aggressive` (API: `aggressive: true`), which may send requests that change data. WebScanX reports findings and does not fix or exploit them.
- **Resource limits.** At most 2 scans run at once, request bodies are capped at 64 KB, timeouts and rate delay are bounded, and finished scans are kept in memory only (20 max).
- **No history on disk.** Reports are written only where you save them.

## Known limits
- Loopback targets are allowed by design; do not expose the engine's port via forwarding or a proxy.
- Any program running as you on the same machine can read the token (it is printed and in the served page) and so can drive scans; the token stops other websites, not local malware.
- Redaction in reports is pattern-based and can miss values.
- DNS pinning covers WebScanX's own connections; the scanner cannot verify that you are authorised, the confirmation is an honour-based gate.
- Detection is heuristic: expect false positives and misses.
- Not independently audited.
