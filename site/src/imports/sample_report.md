# WebScanX report

- **Target:** http://127.0.0.1:63725/
- **Kind:** web
- **Started:** 2026-09-15T10:55:34+00:00
- **Finished:** 2026-09-15T10:55:34+00:00
- **Tool:** WebScanX 0.1.0.dev0
- **Summary:** 8 findings (3 high, 2 medium, 3 low)

## 1. Site served over HTTP (no TLS)  — High

- **Where:** `http://127.0.0.1:63725`
- **Scanner:** `web.tls` · A04:2025 Cryptographic Failures
- **What:** The site is reachable over plain HTTP, so credentials and data travel unencrypted and can be read or altered in transit.
- **How to check:** Open http://127.0.0.1:63725 and confirm the browser shows 'Not secure' with no padlock.
- **Evidence:**

  ```
  No working HTTPS endpoint responded.
  ```
- **Fix:** Serve everything over HTTPS and 301-redirect HTTP to HTTPS; then add HSTS.

## 2. Reflected XSS  — High

- **Where:** `http://127.0.0.1:63725/?q=hello (param: q)`
- **Scanner:** `web.xss` · A05:2025 Injection / CWE-79
- **What:** Input sent to this page is echoed back into the HTML without encoding, so an attacker can craft a link that runs JavaScript in a victim's browser (session theft, actions as the user).
- **How to check:** Request the URL with a test value like "><wsxTEST> in the parameter and view source — if it appears unescaped, it's reflected.
- **Evidence:**

  ```
  Marker reflected unescaped: ...<p>results for "><wsxbab08d764a></p>...
  ```
- **Fix:** Context-encode all output (HTML-encode < > " ' &), prefer a framework's auto-escaping template, and add a Content-Security-Policy.

## 3. SQL injection (error-based)  — High

- **Where:** `http://127.0.0.1:63725/?q=hello (param: q)`
- **Scanner:** `web.sqli` · A05:2025 Injection / CWE-89
- **What:** Input here reaches a database query unsanitised: a single quote produced a database error, meaning an attacker could read or alter the database, bypass logins, or exfiltrate data.
- **How to check:** Append a single quote (') to the value and resend. A raw SQL error in the response confirms it.
- **Evidence:**

  ```
  Probe ' triggered a DB error: SQL syntax; check the MySQL
  ```
- **Fix:** Use parameterised queries / prepared statements (never string concatenation), validate input, and hide raw DB errors from users.

## 4. Missing content-security-policy header  — Medium

- **Where:** `http://127.0.0.1:63725/`
- **Scanner:** `web.headers` · A02:2025 Security Misconfiguration
- **What:** No Content-Security-Policy header. CSP is the browser's main defence against cross-site scripting and data injection.
- **How to check:** Open the site in a browser, check the Network tab response headers for 'Content-Security-Policy'. Absent = flagged.
- **Fix:** Add a Content-Security-Policy header. Start strict, e.g. default-src 'self'; object-src 'none'; frame-ancestors 'none'.

## 5. Form without anti-CSRF token  — Medium

- **Where:** `http://127.0.0.1:63725/login (on http://127.0.0.1:63725/)`
- **Scanner:** `web.csrf` · CWE-352 (Cross-Site Request Forgery)
- **What:** This form changes state (POST) but carries no anti-CSRF token, so another site can force a logged-in user's browser to submit it without their intent.
- **How to check:** Inspect the form's fields: no hidden token (csrf/xsrf/authenticity) means the request can be forged from off-site.
- **Evidence:**

  ```
  POST form to http://127.0.0.1:63725/login; fields: user, pass
  ```
- **Fix:** Add a per-session/per-request anti-CSRF token and verify it server-side; set SameSite=Lax or Strict on session cookies. Most frameworks provide this — enable it.

## 6. Missing x-content-type-options header  — Low

- **Where:** `http://127.0.0.1:63725/`
- **Scanner:** `web.headers` · A02:2025 Security Misconfiguration
- **What:** No X-Content-Type-Options header. The browser may MIME-sniff responses and run a file as a different, dangerous type.
- **How to check:** Check the response headers for 'X-Content-Type-Options: nosniff'.
- **Fix:** Add 'X-Content-Type-Options: nosniff' to every response.

## 7. Missing x-frame-options header  — Low

- **Where:** `http://127.0.0.1:63725/`
- **Scanner:** `web.headers` · A02:2025 Security Misconfiguration
- **What:** No X-Frame-Options / CSP frame-ancestors. The page can be framed by another site for clickjacking.
- **How to check:** Check for 'X-Frame-Options' or a CSP 'frame-ancestors' directive.
- **Fix:** Add 'X-Frame-Options: DENY' or CSP 'frame-ancestors none'.

## 8. Missing referrer-policy header  — Low

- **Where:** `http://127.0.0.1:63725/`
- **Scanner:** `web.headers` · A02:2025 Security Misconfiguration
- **What:** No Referrer-Policy header. Full URLs (which may contain sensitive data) can leak to other sites via the Referer header.
- **How to check:** Check the response headers for 'Referrer-Policy'.
- **Fix:** Add 'Referrer-Policy: strict-origin-when-cross-origin' or stricter.
