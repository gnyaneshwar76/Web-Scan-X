# WebScanX report

- **Target:** http://127.0.0.1:61016/
- **Kind:** web
- **Started:** 2026-09-16T13:22:38+00:00
- **Finished:** 2026-09-16T13:22:39+00:00
- **Tool:** WebScanX 0.1.0.dev0
- **Summary:** 24 findings (11 high, 8 medium, 5 low)

## 1. Site served over HTTP (no TLS)  — High

- **Where:** `http://127.0.0.1:61016`
- **Scanner:** `web.tls` · A04:2025 Cryptographic Failures
- **What:** The site is reachable over plain HTTP, so credentials and data travel unencrypted and can be read or altered in transit.
- **How to check:** Open http://127.0.0.1:61016 and confirm the browser shows 'Not secure' with no padlock.
- **Evidence:**

  ```
  No working HTTPS endpoint responded.
  ```
- **Fix:** Serve everything over HTTPS and 301-redirect HTTP to HTTPS; then add HSTS.

## 2. Reflected XSS  — High

- **Where:** `http://127.0.0.1:61016/?q=hello (param: q)`
- **Scanner:** `web.xss` · A05:2025 Injection / CWE-79
- **What:** Input sent to this page is echoed back into the HTML without encoding, so an attacker can craft a link that runs JavaScript in a victim's browser (session theft, actions as the user).
- **How to check:** Request the URL with a test value like "><wsxTEST> in the parameter and view source — if it appears unescaped, it's reflected.
- **Evidence:**

  ```
  Marker reflected unescaped: ...<p>results for "><wsxdaeb20f3c4></p>...
  ```
- **Fix:** Context-encode all output (HTML-encode < > " ' &), prefer a framework's auto-escaping template, and add a Content-Security-Policy.

## 3. SQL injection (error-based)  — High

- **Where:** `http://127.0.0.1:61016/?q=hello (param: q)`
- **Scanner:** `web.sqli` · A05:2025 Injection / CWE-89
- **What:** Input here reaches a database query unsanitised: a single quote produced a database error, meaning an attacker could read or alter the database, bypass logins, or exfiltrate data.
- **How to check:** Append a single quote (') to the value and resend. A raw SQL error in the response confirms it.
- **Evidence:**

  ```
  Probe ' triggered a DB error: SQL syntax; check the MySQL
  ```
- **Fix:** Use parameterised queries / prepared statements (never string concatenation), validate input, and hide raw DB errors from users.

## 4. Permissive CORS policy  — High

- **Where:** `http://127.0.0.1:61016/`
- **Scanner:** `web.cors` · A02:2025 Security Misconfiguration / CWE-942
- **What:** The server returned Access-Control-Allow-Origin: https://evil.example with Allow-Credentials: true, so any origin can read authenticated responses (session data, etc.). A too-open CORS policy can let untrusted websites read this site's responses.
- **How to check:** curl -s -I -H 'Origin: https://evil.example' http://127.0.0.1:61016/ | grep -i access-control — see if the origin is reflected or set to '*'.
- **Evidence:**

  ```
  Origin: https://evil.example  ->  Access-Control-Allow-Origin: https://evil.example; Access-Control-Allow-Credentials: true
  ```
- **Fix:** Allow only an explicit allow-list of trusted origins; never reflect arbitrary origins, and never combine a wildcard/reflected origin with Allow-Credentials.

## 5. Exposed .env configuration file  — High

- **Where:** `http://127.0.0.1:61016/.env`
- **Scanner:** `web.disclosure` · A02:2025 Security Misconfiguration
- **What:** A file that should not be publicly reachable is being served. It can leak source code, credentials, or internal configuration.
- **How to check:** Open http://127.0.0.1:61016/.env in a browser — if it returns content instead of 404, it's exposed.
- **Evidence:**

  ```
  HTTP 200, body starts: 'SECRET=1 API_KEY=abc123'
  ```
- **Fix:** Block access to this path at the web server, and remove the file from the web root if it doesn't belong there.

## 6. Exposed .htaccess file  — High

- **Where:** `http://127.0.0.1:61016/.htaccess`
- **Scanner:** `web.disclosure` · A02:2025 Security Misconfiguration
- **What:** A file that should not be publicly reachable is being served. It can leak source code, credentials, or internal configuration.
- **How to check:** Open http://127.0.0.1:61016/.htaccess in a browser — if it returns content instead of 404, it's exposed.
- **Evidence:**

  ```
  HTTP 200, body starts: '<a href="/?q=hello">search</a><a href="/go?next=/home">next</a><a href="/debug">debug</a><!-- key AKIAIOSFODNN7EXAMPLE -'
  ```
- **Fix:** Block access to this path at the web server, and remove the file from the web root if it doesn't belong there.

## 7. Exposed PHP config backup  — High

- **Where:** `http://127.0.0.1:61016/config.php.bak`
- **Scanner:** `web.disclosure` · A02:2025 Security Misconfiguration
- **What:** A file that should not be publicly reachable is being served. It can leak source code, credentials, or internal configuration.
- **How to check:** Open http://127.0.0.1:61016/config.php.bak in a browser — if it returns content instead of 404, it's exposed.
- **Evidence:**

  ```
  HTTP 200, body starts: '<a href="/?q=hello">search</a><a href="/go?next=/home">next</a><a href="/debug">debug</a><!-- key AKIAIOSFODNN7EXAMPLE -'
  ```
- **Fix:** Block access to this path at the web server, and remove the file from the web root if it doesn't belong there.

## 8. Exposed .DS_Store file  — High

- **Where:** `http://127.0.0.1:61016/.DS_Store`
- **Scanner:** `web.disclosure` · A02:2025 Security Misconfiguration
- **What:** A file that should not be publicly reachable is being served. It can leak source code, credentials, or internal configuration.
- **How to check:** Open http://127.0.0.1:61016/.DS_Store in a browser — if it returns content instead of 404, it's exposed.
- **Evidence:**

  ```
  HTTP 200, body starts: '<a href="/?q=hello">search</a><a href="/go?next=/home">next</a><a href="/debug">debug</a><!-- key AKIAIOSFODNN7EXAMPLE -'
  ```
- **Fix:** Block access to this path at the web server, and remove the file from the web root if it doesn't belong there.

## 9. AWS access key ID exposed in page source  — High

- **Where:** `http://127.0.0.1:61016/`
- **Scanner:** `web.secrets` · A04:2025 Cryptographic Failures / CWE-312
- **What:** A AWS access key ID appears in this page's response. Secrets in client-served content are readable by anyone and must be treated as compromised.
- **How to check:** View source of http://127.0.0.1:61016/ and search for the value.
- **Evidence:**

  ```
  AWS access key ID: AKIAIO…MPLE
  ```
- **Fix:** Remove the secret from client-served code, rotate it immediately, and keep secrets server-side / in a vault.

## 10. AWS access key ID exposed in page source  — High

- **Where:** `http://127.0.0.1:61016/go?next=/home`
- **Scanner:** `web.secrets` · A04:2025 Cryptographic Failures / CWE-312
- **What:** A AWS access key ID appears in this page's response. Secrets in client-served content are readable by anyone and must be treated as compromised.
- **How to check:** View source of http://127.0.0.1:61016/go?next=/home and search for the value.
- **Evidence:**

  ```
  AWS access key ID: AKIAIO…MPLE
  ```
- **Fix:** Remove the secret from client-served code, rotate it immediately, and keep secrets server-side / in a vault.

## 11. Password form transmitted insecurely  — High

- **Where:** `http://127.0.0.1:61016/login (on http://127.0.0.1:61016/)`
- **Scanner:** `web.forms` · A04:2025 Cryptographic Failures / CWE-319
- **What:** A form containing a password field submits over plain HTTP. Credentials can be intercepted in transit or leaked through browser history, proxies, and server logs.
- **How to check:** Inspect the form's action URL and method; a password field with an http:// action or method=GET confirms it.
- **Evidence:**

  ```
  method=POST, action=http://127.0.0.1:61016/login, fields=user, password
  ```
- **Fix:** Submit credential forms over HTTPS using POST; never place secrets in a GET query string.

## 12. Cookie 'sess' missing Secure, HttpOnly  — Medium

- **Where:** `http://127.0.0.1:61016/`
- **Scanner:** `web.headers` · A02:2025 Security Misconfiguration
- **What:** The cookie 'sess' is set without the Secure, HttpOnly flag(s), leaving it exposed to theft or cross-site sending.
- **How to check:** Inspect the Set-Cookie response header for this cookie and confirm the flags are absent.
- **Evidence:**

  ```
  Set-Cookie: sess=1; SameSite=None; Path=/
  ```
- **Fix:** Set Secure and HttpOnly on session cookies, and SameSite=Lax or Strict to limit cross-site sending.

## 13. Form without anti-CSRF token  — Medium

- **Where:** `http://127.0.0.1:61016/login (on http://127.0.0.1:61016/)`
- **Scanner:** `web.csrf` · CWE-352 (Cross-Site Request Forgery)
- **What:** This form changes state (POST) but carries no anti-CSRF token, so another site can force a logged-in user's browser to submit it without their intent.
- **How to check:** Inspect the form's fields: no hidden token (csrf/xsrf/authenticity) means the request can be forged from off-site.
- **Evidence:**

  ```
  POST form to http://127.0.0.1:61016/login; fields: user, password
  ```
- **Fix:** Add a per-session/per-request anti-CSRF token and verify it server-side; set SameSite=Lax or Strict on session cookies. Most frameworks provide this — enable it.

## 14. Form without anti-CSRF token  — Medium

- **Where:** `http://127.0.0.1:61016/login (on http://127.0.0.1:61016/home)`
- **Scanner:** `web.csrf` · CWE-352 (Cross-Site Request Forgery)
- **What:** This form changes state (POST) but carries no anti-CSRF token, so another site can force a logged-in user's browser to submit it without their intent.
- **How to check:** Inspect the form's fields: no hidden token (csrf/xsrf/authenticity) means the request can be forged from off-site.
- **Evidence:**

  ```
  POST form to http://127.0.0.1:61016/login; fields: user, password
  ```
- **Fix:** Add a per-session/per-request anti-CSRF token and verify it server-side; set SameSite=Lax or Strict on session cookies. Most frameworks provide this — enable it.

## 15. Open redirect  — Medium

- **Where:** `http://127.0.0.1:61016/go?next=/home (param: next)`
- **Scanner:** `web.redirect` · A01:2025 Broken Access Control / CWE-601
- **What:** This parameter redirects to any URL it's given, including external sites. Attackers use it to make phishing links look like they point at your trusted domain, and to steal OAuth tokens.
- **How to check:** Visit http://127.0.0.1:61016/go?next=https%3A%2F%2Fevil.example%2F and confirm the browser lands on evil.example instead of staying on this site.
- **Evidence:**

  ```
  next=https://evil.example/  ->  302 Location: https://evil.example/
  ```
- **Fix:** Don't redirect to user-supplied URLs. Allow only relative paths or an allow-list of known hosts; reject absolute external URLs.

## 16. Risky HTTP methods enabled: DELETE, PUT  — Medium

- **Where:** `http://127.0.0.1:61016/`
- **Scanner:** `web.methods` · A02:2025 Security Misconfiguration / CWE-650
- **What:** The server advertises write/diagnostic HTTP methods that most sites don't need. Left enabled they widen the attack surface (file upload, deletion, request tracing).
- **How to check:** curl -s -i -X OPTIONS http://127.0.0.1:61016/ | grep -i allow
- **Evidence:**

  ```
  Allow: GET, POST, PUT, DELETE, OPTIONS
  ```
- **Fix:** Disable methods the application doesn't use; typically allow only GET, HEAD, POST (and OPTIONS for CORS).

## 17. HTTP TRACE enabled (Cross-Site Tracing)  — Medium

- **Where:** `http://127.0.0.1:61016/`
- **Scanner:** `web.methods` · A02:2025 Security Misconfiguration / CWE-650
- **What:** TRACE echoes the request back, which can be abused to read cookies or auth headers even when HttpOnly is set (Cross-Site Tracing).
- **How to check:** curl -s -i -X TRACE http://127.0.0.1:61016/ — a 200 that echoes the request confirms it.
- **Evidence:**

  ```
  TRACE returned 200 and echoed the request.
  ```
- **Fix:** Disable the TRACE method at the web server / load balancer.

## 18. Weak Content-Security-Policy  — Medium

- **Where:** `http://127.0.0.1:61016/`
- **Scanner:** `web.csp` · A02:2025 Security Misconfiguration / CWE-693
- **What:** A CSP is present but has gaps that reduce its protection against cross-site scripting and content injection: 'unsafe-inline' allows inline scripts/styles (defeats much of XSS protection); wildcard '*' source in default-src; no object-src 'none' (plugins/embeds not locked down); no base-uri (allows <base> tag injection).
- **How to check:** Inspect the Content-Security-Policy response header and review each directive against the OWASP CSP cheat sheet.
- **Evidence:**

  ```
  Content-Security-Policy: default-src *; script-src 'unsafe-inline'
  ```
- **Fix:** Remove 'unsafe-inline'/'unsafe-eval' (use nonces or hashes), avoid wildcard sources, and add object-src 'none' and base-uri 'self'.

## 19. Cookie 'sess': SameSite=None without Secure  — Medium

- **Where:** `http://127.0.0.1:61016/`
- **Scanner:** `web.cookies` · A02:2025 Security Misconfiguration / CWE-1275
- **What:** The cookie 'sess' has a policy problem: SameSite=None without Secure — browsers reject it and it is sent cross-site.
- **How to check:** Inspect the Set-Cookie response header for this cookie.
- **Evidence:**

  ```
  Set-Cookie: sess=1; SameSite=None; Path=/
  ```
- **Fix:** Set Secure whenever SameSite=None, and follow the __Host-/__Secure- prefix rules (Secure, Path=/, no Domain).

## 20. Missing x-content-type-options header  — Low

- **Where:** `http://127.0.0.1:61016/`
- **Scanner:** `web.headers` · A02:2025 Security Misconfiguration
- **What:** No X-Content-Type-Options header. The browser may MIME-sniff responses and run a file as a different, dangerous type.
- **How to check:** Check the response headers for 'X-Content-Type-Options: nosniff'.
- **Fix:** Add 'X-Content-Type-Options: nosniff' to every response.

## 21. Missing x-frame-options header  — Low

- **Where:** `http://127.0.0.1:61016/`
- **Scanner:** `web.headers` · A02:2025 Security Misconfiguration
- **What:** No X-Frame-Options / CSP frame-ancestors. The page can be framed by another site for clickjacking.
- **How to check:** Check for 'X-Frame-Options' or a CSP 'frame-ancestors' directive.
- **Fix:** Add 'X-Frame-Options: DENY' or CSP 'frame-ancestors none'.

## 22. Missing referrer-policy header  — Low

- **Where:** `http://127.0.0.1:61016/`
- **Scanner:** `web.headers` · A02:2025 Security Misconfiguration
- **What:** No Referrer-Policy header. Full URLs (which may contain sensitive data) can leak to other sites via the Referer header.
- **How to check:** Check the response headers for 'Referrer-Policy'.
- **Fix:** Add 'Referrer-Policy: strict-origin-when-cross-origin' or stricter.

## 23. Version disclosed in server header  — Low

- **Where:** `http://127.0.0.1:61016/`
- **Scanner:** `web.disclosure` · A02:2025 Security Misconfiguration
- **What:** The server header advertises exact software and version (TestServer/1.0), helping an attacker match known exploits.
- **How to check:** curl -sI http://127.0.0.1:61016/ | grep -i server
- **Evidence:**

  ```
  server: TestServer/1.0
  ```
- **Fix:** Suppress or genericise version banners (e.g. ServerTokens Prod, server_tokens off, remove X-Powered-By).

## 24. Verbose error exposed (Python traceback)  — Low

- **Where:** `http://127.0.0.1:61016/debug`
- **Scanner:** `web.errors` · A02:2025 Security Misconfiguration / CWE-209
- **What:** The page reveals a stack trace or debug output. These leak file paths, framework versions, and internal logic that help an attacker.
- **How to check:** Open http://127.0.0.1:61016/debug — a raw stack trace or debug page instead of a friendly error confirms it.
- **Evidence:**

  ```
  Matched Python traceback: 'Traceback (most recent call last)'
  ```
- **Fix:** Turn off debug mode in production and return generic error pages; log details server-side only.
