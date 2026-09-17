// WebScanX — demo findings + the Results/Report component shared by Shop and Dashboard.
const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const MODULES = { headers: "Security headers", tls: "TLS / certificates", xss: "XSS", sqli: "SQL injection", csrf: "CSRF & cookies" };
const TARGET = "https://demo.webscanx.internal";

const FINDINGS = [
  { id: "f1", sev: "high", title: "Reflected XSS in ?q parameter", loc: "/search?q=", module: "xss", status: "new",
    what: "The search box sends your text back into the page without cleaning it. An attacker can make a link that runs their own script in a visitor's browser.",
    check: ["Run the command below.", "If the script tag comes back unchanged in the response, the issue is real."],
    cmd: `curl -s "${TARGET}/search?q=%3Cscript%3Ealert(1)%3C/script%3E" | grep -i "<script>alert"`,
    evidence: `GET /search?q=<script>alert(1)</script>\nHTTP/1.1 200 OK\n\n<div class="query-echo">\n  Results for: <script>alert(1)</script>\n</div>`, hl: "<script>alert(1)</script>",
    fix: ["Encode user input before putting it into HTML (use your template engine's auto-escaping).", "Add a Content-Security-Policy header that blocks inline scripts."],
    refs: "OWASP A03 · CWE-79" },
  { id: "f2", sev: "high", title: "Missing Content-Security-Policy header", loc: "/", module: "headers", status: "new",
    what: "Your pages don't tell the browser which scripts are allowed to run. If any injection slips through, nothing stops it.",
    check: ["Run the command below.", "If no content-security-policy line is printed, the header is missing."],
    cmd: `curl -sI ${TARGET}/ | grep -i content-security-policy`,
    evidence: "HTTP/1.1 200 OK\nContent-Type: text/html; charset=utf-8\nServer: nginx/1.18.0\n(no Content-Security-Policy header)", hl: "(no Content-Security-Policy header)",
    fix: ["Start with: Content-Security-Policy: default-src 'self'; object-src 'none'", "Roll it out in report-only mode first, then enforce."],
    refs: "OWASP A05 · CWE-693" },
  { id: "f3", sev: "medium", title: "TLS 1.0 enabled", loc: ":443", module: "tls", status: "seen",
    what: "The server still accepts TLS 1.0, an old encryption version with known weaknesses. Modern browsers no longer need it.",
    check: ["Run the command below.", "If a certificate chain is printed, TLS 1.0 is accepted."],
    cmd: "openssl s_client -connect demo.webscanx.internal:443 -tls1 </dev/null",
    evidence: "CONNECTED(00000003)\nProtocol  : TLSv1\nCipher    : ECDHE-RSA-AES128-SHA", hl: "Protocol  : TLSv1",
    fix: ["Allow only TLS 1.2 and 1.3 (nginx: ssl_protocols TLSv1.2 TLSv1.3;).", "Reload the server and re-run the check."],
    refs: "OWASP A02 · CWE-326" },
  { id: "f4", sev: "medium", title: "Cookie without Secure flag", loc: "/login", module: "csrf", status: "new",
    what: "The login session cookie can be sent over plain HTTP. Anyone on the same network could read it and take over the session.",
    check: ["Run the command below.", "If the session cookie line has no Secure attribute, the issue is real."],
    cmd: `curl -sI -X POST ${TARGET}/login | grep -i set-cookie`,
    evidence: "Set-Cookie: session_token=9f8a2b3c; Path=/; HttpOnly", hl: "Path=/; HttpOnly",
    fix: ["Add Secure to the session cookie.", "Also set SameSite=Lax (or Strict)."],
    refs: "OWASP A05 · CWE-614" },
  { id: "f5", sev: "medium", title: "SQL error message disclosed", loc: "/api/items", module: "sqli", status: "new",
    what: "A single quote in a parameter makes the page show a raw database error. That reveals your database and hints the input reaches a query unsafely.",
    check: ["Run the command below.", "If the response contains a database error, the issue is real."],
    cmd: `curl -s "${TARGET}/api/items?category=books%27"`,
    evidence: 'HTTP/1.1 500 Internal Server Error\n\nERROR: syntax error at or near "\'" at character 42', hl: 'ERROR: syntax error at or near "\'"',
    fix: ["Use parameterized queries for every database call.", "Return a generic error to users; log details on the server only."],
    refs: "OWASP A03 · CWE-89" },
  { id: "f6", sev: "low", title: "Missing X-Content-Type-Options header", loc: "/", module: "headers", status: "seen",
    what: "Browsers may guess a file's type and treat an upload as a script. This header tells them not to guess.",
    check: ["Run the command below.", "If nothing is printed, the header is missing."],
    cmd: `curl -sI ${TARGET}/ | grep -i x-content-type-options`, evidence: "(no X-Content-Type-Options header)", hl: "(no X-Content-Type-Options header)",
    fix: ["Send X-Content-Type-Options: nosniff on every response."], refs: "OWASP A05 · CWE-16" },
  { id: "f7", sev: "low", title: "Missing CSRF token on /account/email", loc: "/account/email", module: "csrf", status: "new",
    what: "The change-email form doesn't include a secret token. Another site could submit it on behalf of a logged-in user.",
    check: ["Open /account/email and view the page source.", "If the form has no hidden csrf token field, the issue is real."],
    cmd: `curl -s ${TARGET}/account/email | grep -i csrf`, evidence: '<form method="POST" action="/account/email">\n  <input name="email">\n</form>', hl: '<input name="email">',
    fix: ["Add a per-session CSRF token to every form that changes data and verify it on the server.", "Set SameSite=Lax on session cookies."],
    refs: "OWASP A01 · CWE-352" },
  { id: "f8", sev: "low", title: "Clickjacking protection missing", loc: "/", module: "headers", status: "ignored",
    what: "Your site can be shown inside another site's invisible frame, tricking users into clicking buttons they can't see.",
    check: ["Run the command below.", "If neither X-Frame-Options nor frame-ancestors is printed, the site can be framed."],
    cmd: `curl -sI ${TARGET}/ | grep -iE "x-frame-options|frame-ancestors"`, evidence: "(no X-Frame-Options or frame-ancestors)", hl: "(no X-Frame-Options or frame-ancestors)",
    fix: ["Add Content-Security-Policy: frame-ancestors 'self' (or X-Frame-Options: DENY)."], refs: "OWASP A05 · CWE-1021" },
  { id: "f9", sev: "low", title: "Missing Strict-Transport-Security header", loc: "/", module: "headers", status: "new",
    what: "Browsers aren't told to always use HTTPS, so a first visit over HTTP can be intercepted.",
    check: ["Run the command below.", "If nothing is printed, HSTS is not enabled."],
    cmd: `curl -sI ${TARGET}/ | grep -i strict-transport-security`, evidence: "(no Strict-Transport-Security header)", hl: "(no Strict-Transport-Security header)",
    fix: ["Send Strict-Transport-Security: max-age=31536000; includeSubDomains"], refs: "OWASP A05 · CWE-319" },
  { id: "f10", sev: "low", title: "Session cookie missing SameSite", loc: "/login", module: "csrf", status: "seen",
    what: "Without SameSite, the browser sends your session cookie on requests started by other sites.",
    check: ["Run the command below.", "If the cookie has no SameSite attribute, the issue is real."],
    cmd: `curl -sI -X POST ${TARGET}/login | grep -i set-cookie`, evidence: "Set-Cookie: session_token=9f8a2b3c; Path=/; HttpOnly", hl: "HttpOnly",
    fix: ["Add SameSite=Lax to the session cookie."], refs: "OWASP A01 · CWE-1275" },
  { id: "f11", sev: "info", title: "Server header shows version (nginx/1.18.0)", loc: "/", module: "headers", status: "seen",
    what: "The server announces its exact version, which helps attackers look up known bugs for it.",
    check: ["Run the command below and look at the Server line."], cmd: `curl -sI ${TARGET}/ | grep -i ^server`,
    evidence: "Server: nginx/1.18.0", hl: "nginx/1.18.0", fix: ["Hide the version (nginx: server_tokens off;)."], refs: "CWE-200" },
  { id: "f12", sev: "info", title: "Directory listing on /static", loc: "/static/", module: "headers", status: "seen",
    what: "Visiting /static/ shows a list of every file in the folder, including ones you may not mean to publish.",
    check: ["Open /static/ in a browser.", "If you see an 'Index of' page, listing is on."], cmd: `curl -s ${TARGET}/static/ | grep -i "index of"`,
    evidence: "<title>Index of /static/</title>", hl: "Index of /static/", fix: ["Turn off directory listing (nginx: autoindex off;)."], refs: "CWE-548" },
  { id: "f13", sev: "info", title: "X-Powered-By header present", loc: "/", module: "headers", status: "new",
    what: "The response names the framework running your site. It's harmless alone but helps attackers pick targets.",
    check: ["Run the command below."], cmd: `curl -sI ${TARGET}/ | grep -i x-powered-by`,
    evidence: "X-Powered-By: Express", hl: "Express", fix: ["Remove the header (Express: app.disable('x-powered-by'))."], refs: "CWE-200" },
  { id: "f14", sev: "info", title: "Referrer-Policy not set", loc: "/", module: "headers", status: "new",
    what: "Full page addresses may be sent to other sites when users click links, sometimes leaking tokens in URLs.",
    check: ["Run the command below. If nothing is printed, no policy is set."], cmd: `curl -sI ${TARGET}/ | grep -i referrer-policy`,
    evidence: "(no Referrer-Policy header)", hl: "(no Referrer-Policy header)", fix: ["Send Referrer-Policy: strict-origin-when-cross-origin"], refs: "CWE-200" },
  { id: "f15", sev: "info", title: "Permissions-Policy not set", loc: "/", module: "headers", status: "new",
    what: "The site doesn't restrict powerful browser features like camera or geolocation for embedded content.",
    check: ["Run the command below. If nothing is printed, no policy is set."], cmd: `curl -sI ${TARGET}/ | grep -i permissions-policy`,
    evidence: "(no Permissions-Policy header)", hl: "(no Permissions-Policy header)", fix: ["Send Permissions-Policy: camera=(), microphone=(), geolocation=()"], refs: "OWASP A05" },
  { id: "f16", sev: "info", title: "Certificate expires in 58 days", loc: ":443", module: "tls", status: "seen",
    what: "The HTTPS certificate is valid but expires on 11 Nov 2026. Renew it before then to avoid browser warnings.",
    check: ["Run the command below and read the notAfter date."], cmd: "echo | openssl s_client -connect demo.webscanx.internal:443 2>/dev/null | openssl x509 -noout -enddate",
    evidence: "notAfter=Nov 11 23:59:59 2026 GMT", hl: "Nov 11 23:59:59 2026", fix: ["Enable automatic renewal (e.g. certbot renew on a timer)."], refs: "—" },
  { id: "f17", sev: "info", title: "Password field allows autocomplete", loc: "/login", module: "csrf", status: "new",
    what: "The browser may save the password on shared computers. Usually fine for personal devices.",
    check: ["View the login page source and look at the password input."], cmd: `curl -s ${TARGET}/login | grep -i 'type="password"'`,
    evidence: '<input type="password" name="password">', hl: 'type="password"', fix: ['Use autocomplete="current-password" so password managers work correctly.'], refs: "CWE-522" },
  { id: "f18", sev: "info", title: "robots.txt lists /admin", loc: "/robots.txt", module: "headers", status: "seen",
    what: "robots.txt points to an admin area. It isn't a vulnerability by itself, but it tells everyone where to look.",
    check: ["Open /robots.txt in a browser."], cmd: `curl -s ${TARGET}/robots.txt`,
    evidence: "User-agent: *\nDisallow: /admin", hl: "Disallow: /admin", fix: ["Protect /admin with authentication; don't rely on robots.txt to hide it."], refs: "CWE-200" },
];

const esc = s => String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const cap = s => s[0].toUpperCase() + s.slice(1);

// Highlight the last occurrence (the reflected/response part, not the request line).
function highlightLast(text, needle) {
  const i = text.lastIndexOf(needle);
  return i < 0 ? text : text.slice(0, i) + `<span class="hl">${needle}</span>` + text.slice(i + needle.length);
}

function countBySev(list) {
  const c = Object.fromEntries(SEVERITIES.map(s => [s, 0]));
  list.forEach(f => c[f.sev]++);
  return c;
}

function toast(msg) {
  let t = document.querySelector(".toast");
  if (!t) { t = document.createElement("div"); t.className = "toast"; t.setAttribute("role", "status"); document.body.append(t); }
  t.textContent = msg; t.classList.add("show");
  clearTimeout(t._h); t._h = setTimeout(() => t.classList.remove("show"), 1800);
}

async function copyText(text) {
  try { await navigator.clipboard.writeText(text); }
  catch { const a = document.createElement("textarea"); a.value = text; document.body.append(a); a.select(); document.execCommand("copy"); a.remove(); }
  toast("Copied to clipboard");
}

// Delegated copy buttons: <button class="copy" data-copy="text">
document.addEventListener("click", e => { const b = e.target.closest("[data-copy]"); if (b) copyText(b.dataset.copy); });

/**
 * Render an interactive report into `root`.
 * opts: { findings, meta:{target,date,duration}, onExport(), onChange(findings), static:bool }
 */
function renderReport(root, opts) {
  const findings = opts.findings;
  const st = { sev: "all", q: "", module: "all", sel: findings[0]?.id };

  root.classList.add("report");
  root.innerHTML = `
    <div class="r-head">
      <div class="meta"><b>${esc(opts.meta.target)}</b><span>${esc(opts.meta.date)}</span><span>${esc(opts.meta.duration)}</span></div>
      ${opts.onExport ? '<button class="btn" data-act="export">Export report</button>' : ""}
    </div>
    <div class="r-sev"><div class="bar" aria-hidden="true"></div><div class="legend"></div></div>
    <div class="r-tools">
      <div class="tabs" role="tablist" aria-label="Filter by severity"></div>
      <input class="input search" type="search" placeholder="Search findings" aria-label="Search findings">
      <select class="input" aria-label="Filter by module"><option value="all">Module: All</option>
        ${Object.entries(MODULES).map(([k, v]) => `<option value="${k}">${v}</option>`).join("")}</select>
    </div>
    <div class="r-body">
      <div class="r-list" tabindex="-1"></div>
      <aside class="r-detail" aria-live="polite"></aside>
    </div>`;

  const $ = s => root.querySelector(s);
  $(".search").addEventListener("input", e => { st.q = e.target.value.toLowerCase(); draw(); });
  $("select").addEventListener("change", e => { st.module = e.target.value; draw(); });
  root.addEventListener("click", e => {
    const tab = e.target.closest(".tab"); if (tab) { st.sev = tab.dataset.sev; draw(); return; }
    const row = e.target.closest("tr.row"); if (row) { st.sel = row.dataset.id; draw(); return; }
    const act = e.target.closest("[data-act]"); if (!act) return;
    const f = findings.find(x => x.id === st.sel);
    if (act.dataset.act === "export") opts.onExport();
    if (act.dataset.act === "reset") { st.sev = "all"; st.q = ""; st.module = "all"; $(".search").value = ""; $("select").value = "all"; draw(); }
    if (f && (act.dataset.act === "seen" || act.dataset.act === "ignore" || act.dataset.act === "new")) {
      f.status = act.dataset.act === "ignore" ? "ignored" : act.dataset.act;
      opts.onChange?.(findings); toast(`Marked as ${f.status}`); draw();
    }
  });
  root.addEventListener("keydown", e => {
    if (!["ArrowDown", "ArrowUp"].includes(e.key) || e.target.matches("input,select")) return;
    const vis = visible(), i = vis.findIndex(f => f.id === st.sel);
    const n = vis[Math.max(0, Math.min(vis.length - 1, i + (e.key === "ArrowDown" ? 1 : -1)))];
    if (n) { e.preventDefault(); st.sel = n.id; draw(); root.querySelector(`tr[data-id="${n.id}"]`)?.scrollIntoView({ block: "nearest" }); }
  });

  function visible() {
    return findings.filter(f => (st.sev === "all" || f.sev === st.sev) && (st.module === "all" || f.module === st.module)
      && (!st.q || (f.title + f.loc + f.module).toLowerCase().includes(st.q)));
  }

  function draw() {
    const c = countBySev(findings), total = findings.length;
    $(".bar").innerHTML = SEVERITIES.filter(s => c[s]).map(s => `<span style="flex:${c[s]};background:var(--${s})"></span>`).join("");
    $(".legend").innerHTML = SEVERITIES.filter(s => c[s]).map(s => `<span class="c-${s}">${c[s]} ${cap(s)}</span>`).join("")
      + `<span class="muted" style="margin-left:auto">${total} findings</span>`;
    $(".tabs").innerHTML = [["all", `All (${total})`], ...SEVERITIES.map(s => [s, `${cap(s)} (${c[s]})`])]
      .map(([k, label]) => `<button class="tab" role="tab" data-sev="${k}" aria-selected="${st.sev === k}" ${k !== "all" && !c[k] ? "disabled" : ""}>${label}</button>`).join("");

    const vis = visible();
    if (!vis.some(f => f.id === st.sel)) st.sel = vis[0]?.id;
    $(".r-list").innerHTML = vis.length ? `
      <table class="findings"><thead><tr><th>Severity</th><th>Finding</th><th>Location</th><th class="mod">Module</th><th class="st">Status</th></tr></thead>
      <tbody>${vis.map(f => `<tr class="row ${f.status} ${f.id === st.sel ? "sel" : ""}" data-id="${f.id}" aria-selected="${f.id === st.sel}">
        <td><span class="pill ${f.sev}">${f.sev}</span></td><td class="t">${esc(f.title)}</td><td class="loc">${esc(f.loc)}</td>
        <td class="mod">${f.module}</td><td class="st">${cap(f.status)}</td></tr>`).join("")}</tbody></table>`
      : `<div class="r-empty"><p>No findings match these filters.</p><button class="btn" data-act="reset">Clear filters</button></div>`;

    const f = findings.find(x => x.id === st.sel);
    $(".r-detail").innerHTML = !f ? `<p class="text2">Select a finding to see what it is and how to fix it.</p>` : `
      <span class="pill ${f.sev}">${f.sev}</span> <span class="label" style="margin-left:6px">${MODULES[f.module]}</span>
      <h3>${esc(f.title)}</h3><div class="path">${esc(opts.meta.target.replace(/^https?:\/\//, ""))}${esc(f.loc)}</div>
      <section><div class="label">What it is</div><p>${esc(f.what)}</p></section>
      <section><div class="label">How to check it yourself</div><ol>${f.check.map(s => `<li>${esc(s)}</li>`).join("")}</ol>
        <pre class="code">${esc(f.cmd)}<button class="copy" data-copy="${esc(f.cmd)}" aria-label="Copy command" title="Copy">⧉</button></pre></section>
      <section><div class="label">Evidence</div><pre class="code">${highlightLast(esc(f.evidence), esc(f.hl))}</pre></section>
      <section><div class="label">How to fix it</div><ul>${f.fix.map(s => `<li>${esc(s)}</li>`).join("")}</ul></section>
      <section><div class="label">References</div><p class="mono" style="font-size:12px">${esc(f.refs)}</p></section>
      ${opts.static ? "" : `<div class="actions">
        ${f.status !== "seen" ? '<button class="btn" data-act="seen">Mark as seen</button>' : ""}
        ${f.status !== "ignored" ? '<button class="btn" data-act="ignore">Ignore</button>' : '<button class="btn" data-act="new">Restore</button>'}
      </div>`}`;
  }
  draw();
}
