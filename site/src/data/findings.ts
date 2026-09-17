export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export const SEV_COLORS: Record<Severity, { text: string; bg: string; bar: string }> = {
  CRITICAL: { text: "#0b0a0a", bg: "#FF3B30", bar: "#FF3B30" },
  HIGH:     { text: "#EF4444", bg: "#EF444420", bar: "#EF4444" },
  MEDIUM:   { text: "#F97316", bg: "#F9731620", bar: "#F97316" },
  LOW:      { text: "#EAB308", bg: "#EAB30820", bar: "#EAB308" },
  INFO:     { text: "#8A8A8A", bg: "#8A8A8A1F", bar: "#8A8A8A" },
};
export type Status = "New" | "Seen" | "Ignored";

export type Finding = {
  id: number;
  severity: Severity;
  name: string;
  path: string;
  module: string;
  status: Status;
  what: string;
  howToCheck: string;
  checkCommand: string;
  evidence: string;
  fix: string;
  refs: string;
};

// Real findings from WebScanX 0.1.0.dev0 scan of http://127.0.0.1:63725/
// Source: src/imports/sample_report.md
export const FINDINGS: Finding[] = [
  {
    id: 1,
    severity: "HIGH",
    name: "Site served over HTTP (no TLS)",
    path: "http://127.0.0.1:63725",
    module: "TLS",
    status: "New",
    what: "The site is reachable over plain HTTP, so credentials and data travel unencrypted and can be read or altered in transit.",
    howToCheck: "Open http://127.0.0.1:63725 and confirm the browser shows 'Not secure' with no padlock.",
    checkCommand: "curl -sI http://127.0.0.1:63725/ | grep -i location",
    evidence: "No working HTTPS endpoint responded.",
    fix: "Serve everything over HTTPS and 301-redirect HTTP to HTTPS; then add HSTS.",
    refs: "web.tls · A04:2025 Cryptographic Failures",
  },
  {
    id: 2,
    severity: "HIGH",
    name: "Reflected XSS",
    path: "/?q=hello (param: q)",
    module: "XSS",
    status: "New",
    what: 'Input sent to this page is echoed back into the HTML without encoding, so an attacker can craft a link that runs JavaScript in a victim\'s browser (session theft, actions as the user).',
    howToCheck: 'Request the URL with a test value like "><wsxTEST> in the parameter and view source — if it appears unescaped, it\'s reflected.',
    checkCommand: 'curl -s "http://127.0.0.1:63725/?q=%22%3EwsxTEST" | grep wsxTEST',
    evidence: 'Marker reflected unescaped: ...<p>results for "><wsxbab08d764a></p>...',
    fix: "Context-encode all output (HTML-encode < > \" ' &), prefer a framework's auto-escaping template, and add a Content-Security-Policy.",
    refs: "web.xss · A05:2025 Injection / CWE-79",
  },
  {
    id: 3,
    severity: "HIGH",
    name: "SQL injection (error-based)",
    path: "/?q=hello (param: q)",
    module: "SQLI",
    status: "New",
    what: "Input here reaches a database query unsanitised: a single quote produced a database error, meaning an attacker could read or alter the database, bypass logins, or exfiltrate data.",
    howToCheck: "Append a single quote (') to the value and resend. A raw SQL error in the response confirms it.",
    checkCommand: "curl -s \"http://127.0.0.1:63725/?q='\" | grep -i sql",
    evidence: "Probe ' triggered a DB error: SQL syntax; check the MySQL",
    fix: "Use parameterised queries / prepared statements (never string concatenation), validate input, and hide raw DB errors from users.",
    refs: "web.sqli · A05:2025 Injection / CWE-89",
  },
  {
    id: 4,
    severity: "MEDIUM",
    name: "Missing Content-Security-Policy header",
    path: "/",
    module: "HEADERS",
    status: "New",
    what: "No Content-Security-Policy header. CSP is the browser's main defence against cross-site scripting and data injection.",
    howToCheck: "Open the site in a browser, check the Network tab response headers for 'Content-Security-Policy'. Absent = flagged.",
    checkCommand: "curl -sI http://127.0.0.1:63725/ | grep -i content-security",
    evidence: "Header absent from response.",
    fix: "Add a Content-Security-Policy header. Start strict, e.g. default-src 'self'; object-src 'none'; frame-ancestors 'none'.",
    refs: "web.headers · A02:2025 Security Misconfiguration",
  },
  {
    id: 5,
    severity: "MEDIUM",
    name: "Form without anti-CSRF token",
    path: "/login",
    module: "CSRF",
    status: "New",
    what: "This form changes state (POST) but carries no anti-CSRF token, so another site can force a logged-in user's browser to submit it without their intent.",
    howToCheck: "Inspect the form's fields: no hidden token (csrf/xsrf/authenticity) means the request can be forged from off-site.",
    checkCommand: "curl -s http://127.0.0.1:63725/login | grep -i csrf",
    evidence: "POST form to http://127.0.0.1:63725/login; fields: user, pass",
    fix: "Add a per-session/per-request anti-CSRF token and verify it server-side; set SameSite=Lax or Strict on session cookies. Most frameworks provide this — enable it.",
    refs: "web.csrf · CWE-352 (Cross-Site Request Forgery)",
  },
  {
    id: 6,
    severity: "LOW",
    name: "Missing X-Content-Type-Options header",
    path: "/",
    module: "HEADERS",
    status: "Seen",
    what: "No X-Content-Type-Options header. The browser may MIME-sniff responses and run a file as a different, dangerous type.",
    howToCheck: "Check the response headers for 'X-Content-Type-Options: nosniff'.",
    checkCommand: "curl -sI http://127.0.0.1:63725/ | grep -i x-content-type",
    evidence: "Header absent from response.",
    fix: "Add 'X-Content-Type-Options: nosniff' to every response.",
    refs: "web.headers · A02:2025 Security Misconfiguration",
  },
  {
    id: 7,
    severity: "LOW",
    name: "Missing X-Frame-Options header",
    path: "/",
    module: "HEADERS",
    status: "Seen",
    what: "No X-Frame-Options / CSP frame-ancestors. The page can be framed by another site for clickjacking.",
    howToCheck: "Check for 'X-Frame-Options' or a CSP 'frame-ancestors' directive.",
    checkCommand: "curl -sI http://127.0.0.1:63725/ | grep -i x-frame",
    evidence: "Header absent from response.",
    fix: "Add 'X-Frame-Options: DENY' or CSP 'frame-ancestors none'.",
    refs: "web.headers · A02:2025 Security Misconfiguration",
  },
  {
    id: 8,
    severity: "LOW",
    name: "Missing Referrer-Policy header",
    path: "/",
    module: "HEADERS",
    status: "Seen",
    what: "No Referrer-Policy header. Full URLs (which may contain sensitive data) can leak to other sites via the Referer header.",
    howToCheck: "Check the response headers for 'Referrer-Policy'.",
    checkCommand: "curl -sI http://127.0.0.1:63725/ | grep -i referrer",
    evidence: "Header absent from response.",
    fix: "Add 'Referrer-Policy: strict-origin-when-cross-origin' or stricter.",
    refs: "web.headers · A02:2025 Security Misconfiguration",
  },
];

export const SCAN_META = {
  target: "http://127.0.0.1:63725/",
  date: "2026-09-15",
  dateDisplay: "15 Sep 2026",
  started: "2026-09-15T10:55:34+00:00",
  duration: "0m 0s",
  tool: "WebScanX v1.0",
  counts: { high: 3, medium: 2, low: 3, info: 0, total: 8 },
};
