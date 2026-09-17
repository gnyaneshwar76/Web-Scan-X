// WebScanX dashboard — hash router, simulated scan, results, history, settings, export.
const DEPTHS = { quick: { name: "Quick", note: "~2 min · headers, TLS, cookies" }, standard: { name: "Standard", note: "~10 min · adds XSS and CSRF" }, deep: { name: "Deep", note: "~45 min · adds SQL injection, full crawl" } };
const DEMO_FACTOR = 12; // ponytail: demo scan runs ~12s; real engine timing replaces this

const store = {
  get(k, d) { try { return JSON.parse(localStorage.getItem("wsx." + k)) ?? d; } catch { return d; } },
  set(k, v) { try { localStorage.setItem("wsx." + k, JSON.stringify(v)); } catch {} },
};

const settings = Object.assign({ depth: "standard", modules: Object.keys(MODULES), folder: "~/Documents", rate: 10, timeout: 15 }, store.get("settings", {}));
const fmtDate = d => new Date(d).toLocaleString("en-GB", { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
const mmss = s => `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(Math.floor(s % 60)).padStart(2, "0")}`;
const allIds = FINDINGS.map(f => f.id);

// Statuses persist across reloads.
const saved = store.get("status", {});
FINDINGS.forEach(f => { if (saved[f.id]) f.status = saved[f.id]; });
const saveStatus = () => store.set("status", Object.fromEntries(FINDINGS.map(f => [f.id, f.status])));

const SEED = [
  ["2026-09-14T14:02", TARGET, "standard", "3m 42s", allIds],
  ["2026-09-12T10:15", "https://staging.example.com", "deep", "41m 09s", allIds.slice(0, 16)],
  ["2026-09-10T18:40", "http://localhost:3000", "quick", "1m 58s", ["f3", "f6", "f9", "f11", "f13"]],
  ["2026-09-08T09:22", "https://staging.example.com", "standard", "9m 31s", allIds.slice(0, 14)],
  ["2026-09-05T16:05", TARGET, "standard", "3m 50s", allIds.slice(1)],
  ["2026-09-02T11:47", "http://localhost:8000", "quick", "2m 04s", ["f6", "f9", "f14", "f15"]],
].map(([date, target, depth, duration, ids], i) => ({ id: "s" + i, date, target, depth, duration, ids }));
let history = store.get("history", SEED);
let current = history[0];
const saveHistory = () => store.set("history", history);

let scan = null; // live scan state
const main = document.getElementById("main");

function route() {
  const view = (location.hash.slice(1) || "new").split("/")[0];
  document.querySelectorAll("nav.main a").forEach(a => a.toggleAttribute("aria-current", a.hash === "#" + (view === "scan" ? "new" : view)));
  document.querySelectorAll("nav.main a[aria-current]").forEach(a => a.setAttribute("aria-current", "page"));
  if (view !== "scan" && scan?.timer && !scan.finished) { /* keep scanning in background */ }
  ({ new: viewNew, scan: viewScan, results: viewResults, history: viewHistory, settings: viewSettings }[view] || viewNew)();
  main.scrollTop = 0;
  document.title = `WebScanX — ${cap(view === "new" ? "New scan" : view)}`;
}
addEventListener("hashchange", route);

/* ---------- New scan ---------- */
function viewNew() {
  if (scan && !scan.finished) { location.hash = "#scan"; return; }
  const recents = [...new Map(history.map(h => [h.target, h])).values()].slice(0, 3);
  main.innerHTML = `<div class="view">
    <h1>New Scan</h1><p class="sub">Scan a website you own or have written permission to test.</p>
    <div class="ns">
      <form id="scanForm" novalidate>
        <div class="field"><label class="label" for="target"><span>Target</span><span class="muted">http / https</span></label>
          <input class="input big" id="target" name="target" type="url" placeholder="https://staging.example.com" autocomplete="off" spellcheck="false">
          <div class="err" id="targetErr" hidden>Enter a full URL including http:// or https://</div></div>
        <div class="field"><div class="label"><span>Scan depth</span></div>
          <div class="seg">${Object.entries(DEPTHS).map(([k, d]) => `<label><input type="radio" name="depth" value="${k}" ${settings.depth === k ? "checked" : ""}><b>${d.name}</b><span>${d.note}</span></label>`).join("")}</div></div>
        <div class="field"><div class="label"><span>Checks</span><span class="muted" id="modCount"></span></div>
          <div class="checks">${Object.entries(MODULES).map(([k, v]) => `<label><input class="check" type="checkbox" name="modules" value="${k}" ${settings.modules.includes(k) ? "checked" : ""}><span>${v}</span><span>${{ headers: "CSP · HSTS · X-Frame-Options", tls: "protocols · ciphers · expiry", xss: "reflected · stored · DOM", sqli: "error-based · blind", csrf: "tokens · SameSite · Secure" }[k]}</span></label>`).join("")}</div></div>
        <label class="auth"><input class="check" type="checkbox" id="auth"><div><b>I am authorized to scan this target</b><span>Scanning systems you don't own or don't have written permission to test may be illegal.</span></div></label>
        <button class="btn btn-primary btn-lg" id="startBtn" disabled>Start scan</button>
        <p class="hint" id="startHint">Tick the authorization box to start.</p>
      </form>
      <div class="recent"><h2 class="label">Recent targets</h2>
        ${recents.map(r => `<button type="button" data-target="${esc(r.target)}"><b>${esc(r.target)}</b><span>${fmtDate(r.date)} · ${DEPTHS[r.depth].name}</span></button>`).join("")}
        <p class="muted" style="font-size:12px">Targets are stored on this machine only.</p></div>
    </div></div>`;

  const form = main.querySelector("#scanForm"), t = form.querySelector("#target"), auth = form.querySelector("#auth"), btn = form.querySelector("#startBtn"), hint = form.querySelector("#startHint");
  const validUrl = () => { try { const u = new URL(t.value.trim()); return /^https?:$/.test(u.protocol) && !!u.hostname; } catch { return false; } };
  const mods = () => [...form.querySelectorAll("[name=modules]:checked")].map(i => i.value);
  const sync = () => {
    const m = mods().length;
    main.querySelector("#modCount").textContent = `${m} of 5 selected`;
    btn.disabled = !auth.checked || !m;
    hint.textContent = !auth.checked ? "Tick the authorization box to start." : !m ? "Select at least one check." : "Ready.";
  };
  form.addEventListener("input", sync);
  t.addEventListener("blur", () => { const bad = t.value && !validUrl(); t.classList.toggle("invalid", bad); main.querySelector("#targetErr").hidden = !bad; });
  main.querySelector(".recent").addEventListener("click", e => { const b = e.target.closest("[data-target]"); if (b) { t.value = b.dataset.target; t.dispatchEvent(new Event("blur")); t.focus(); } });
  form.addEventListener("submit", e => {
    e.preventDefault();
    if (!validUrl()) { t.classList.add("invalid"); main.querySelector("#targetErr").hidden = false; t.focus(); return; }
    startScan(new URL(t.value.trim()).href.replace(/\/$/, ""), form.depth.value, mods());
  });
  sync();
}

/* ---------- Scanning (simulated) ---------- */
function startScan(target, depth, modules) {
  const plan = modules.map(m => ({ m, ids: FINDINGS.filter(f => f.module === m).map(f => f.id) }));
  scan = { target, depth, modules, plan, found: [], log: [], start: Date.now(), progress: 0, finished: false, stopped: false };
  scan.timer = setInterval(tick, 250);
  location.hash = "#scan";
}

function tick() {
  const s = scan, total = DEMO_FACTOR * 1000, elapsed = Date.now() - s.start;
  s.progress = Math.min(1, elapsed / total);
  const per = 1 / s.plan.length;
  s.plan.forEach((p, i) => {
    const local = (s.progress - i * per) / per; // 0..1 within this module
    p.ids.forEach((id, j) => {
      if (local >= (j + 1) / (p.ids.length + 1) && !s.found.includes(id)) {
        s.found.push(id);
        const f = FINDINGS.find(x => x.id === id);
        s.log.push(`[${mmss(elapsed / 1000)}] FINDING ${f.sev.toUpperCase()} ${f.title} (${f.loc})`);
      }
    });
    if (local > 0 && local < 1 && Math.random() < .5) s.log.push(`[${mmss(elapsed / 1000)}] GET ${s.target.replace(/^https?:\/\/[^/]+/, "") || ""}/${["search?q=test", "login", "api/items?category=books", "static/", "account/email", ""][Math.floor(Math.random() * 6)]} 200`);
  });
  if (s.progress >= 1) finishScan(false);
  if (location.hash === "#scan") drawScan();
}

function finishScan(stopped) {
  const s = scan; clearInterval(s.timer); s.finished = true; s.stopped = stopped;
  s.duration = mmss((Date.now() - s.start) / 1000).replace(":", "m ") + "s";
  s.log.push(`[${mmss((Date.now() - s.start) / 1000)}] ${stopped ? "STOPPED by user" : "DONE"} — ${s.found.length} findings`);
  const entry = { id: "s" + Date.now(), date: new Date().toISOString(), target: s.target, depth: s.depth, duration: s.duration, ids: [...s.found] };
  history.unshift(entry); saveHistory(); current = entry;
  if (location.hash === "#scan") drawScan();
}

function viewScan() {
  if (!scan) { location.hash = "#new"; return; }
  main.innerHTML = `<div class="view">
    <div class="top"><h1 id="scanTitle">Scanning</h1><span class="mono">${esc(scan.target)}</span><span class="tag">${scan.depth}</span>
      <span class="grow"></span><span class="mono text2" id="elapsed"></span><button class="btn" id="stopBtn">Stop scan</button></div>
    <div id="doneBox"></div>
    <div class="progress"><span id="bar"></span></div><div class="pline"><span id="now"></span><span id="pct"></span></div>
    <div class="grid5" id="mods"></div><div class="grid5" id="counts"></div>
    <div class="panel"><header><b>Live findings</b><span class="mono muted" style="font-size:12px">newest first</span></header>
      <table class="findings live"><tbody id="live"></tbody></table><div class="r-empty" id="liveEmpty">Waiting for the first finding…</div></div>
    <details class="log"><summary>Raw log</summary><pre id="log"></pre></details></div>`;
  main.querySelector("#stopBtn").onclick = () => { if (!scan.finished && confirm("Stop this scan? Findings so far are kept.")) finishScan(true); };
  scan.drawnFound = -1;
  drawScan();
}

function drawScan() {
  const s = scan, $ = id => main.querySelector("#" + id);
  if (!$("bar")) return;
  const elapsed = ((s.finished ? 0 : Date.now()) - s.start) / 1000;
  $("bar").style.width = (s.progress * 100).toFixed(1) + "%";
  $("pct").textContent = Math.round(s.progress * 100) + "%";
  const idx = Math.min(s.plan.length - 1, Math.floor(s.progress * s.plan.length));
  $("now").textContent = s.finished ? (s.stopped ? "Stopped" : "All checks finished") : `Checking ${MODULES[s.plan[idx].m]}…`;
  if (!s.finished) $("elapsed").textContent = mmss(elapsed);
  $("mods").innerHTML = Object.entries(MODULES).map(([k, v]) => {
    const i = s.plan.findIndex(p => p.m === k);
    const state = i < 0 ? "skipped" : s.finished ? (i <= idx || !s.stopped ? "done" : "skipped") : i < idx ? "done" : i === idx ? "running" : "queued";
    return `<div><div style="font-size:13px">${v}</div><div class="mstate ${state}">${state === "done" ? "✓ Done" : state === "running" ? "■ Running" : cap(state)}</div></div>`;
  }).join("");
  const c = countBySev(s.found.map(id => FINDINGS.find(f => f.id === id)));
  $("counts").innerHTML = SEVERITIES.map(sv => `<div class="counter"><span class="pill ${sv}">${sv}</span><b class="${c[sv] ? "c-" + sv : "muted"}">${c[sv]}</b></div>`).join("");
  if (s.drawnFound !== s.found.length) {
    s.drawnFound = s.found.length;
    $("live").innerHTML = [...s.found].reverse().map(id => { const f = FINDINGS.find(x => x.id === id); return `<tr><td style="width:100px"><span class="pill ${f.sev}">${f.sev}</span></td><td class="t">${esc(f.title)}</td><td class="loc">${esc(f.loc)}</td></tr>`; }).join("");
    $("liveEmpty").hidden = s.found.length > 0;
  }
  const log = $("log"); log.textContent = s.log.slice(-200).join("\n"); log.scrollTop = log.scrollHeight;
  if (s.finished && !$("doneBox").innerHTML) {
    $("scanTitle").textContent = s.stopped ? "Scan stopped" : "Scan complete";
    $("stopBtn").replaceWith(Object.assign(document.createElement("a"), { className: "btn", href: "#new", textContent: "New scan" }));
    $("elapsed").textContent = s.duration;
    $("doneBox").innerHTML = `<div class="done-box"><p><b>${s.found.length} findings</b> on ${esc(s.target)}. ${s.stopped ? "The scan was stopped early." : "Every finding has a plain-language explanation and a fix."}</p><a class="btn btn-primary" href="#results">View results</a></div>`;
    scan = Object.assign(s, { shown: true });
  }
}

/* ---------- Results ---------- */
function viewResults() {
  if (!current) { main.innerHTML = `<div class="view"><h1>Results</h1><div class="empty-state" style="margin-top:24px"><p>No scans yet.</p><a class="btn btn-primary" href="#new">Start a scan</a></div></div>`; return; }
  const list = FINDINGS.filter(f => current.ids.includes(f.id));
  main.innerHTML = `<div class="view"><div class="top"><h1>Results</h1><span class="grow"></span><a class="btn" href="#history">All scans</a></div><div id="reportRoot"></div></div>`;
  if (!list.length) { main.querySelector("#reportRoot").outerHTML = `<div class="empty-state"><p>No findings on ${esc(current.target)}. Nice.</p></div>`; return; }
  renderReport(main.querySelector("#reportRoot"), {
    findings: list, meta: { target: current.target, date: fmtDate(current.date), duration: current.duration },
    onExport: () => openExport(current), onChange: saveStatus,
  });
}

/* ---------- History ---------- */
function viewHistory() {
  main.innerHTML = `<div class="view"><h1>History</h1><p class="sub">Stored locally in <span class="mono">~/.webscanx/scans</span></p>
    <div class="htools"><input class="input" type="search" id="hq" placeholder="Search targets" aria-label="Search targets"></div>
    <div class="tbl-wrap"><table class="findings"><thead><tr><th>Date</th><th>Target</th><th>Depth</th><th>Duration</th><th>Findings</th><th class="st">Actions</th></tr></thead><tbody id="hrows"></tbody></table></div></div>`;
  const draw = () => {
    const q = main.querySelector("#hq").value.toLowerCase(), rows = history.filter(h => h.target.toLowerCase().includes(q));
    main.querySelector("#hrows").innerHTML = rows.length ? rows.map(h => {
      const c = countBySev(FINDINGS.filter(f => h.ids.includes(f.id)));
      return `<tr data-id="${h.id}"><td class="loc">${fmtDate(h.date)}</td><td class="mono" style="font-size:12px">${esc(h.target)}</td><td><span class="tag">${h.depth}</span></td><td class="loc">${h.duration}</td>
        <td><span class="minibar">${SEVERITIES.filter(s => c[s]).map(s => `<span style="flex:${c[s]};background:var(--${s})"></span>`).join("")}</span><span class="mono" style="font-size:12px">${SEVERITIES.filter(s => c[s]).map(s => `<span class="c-${s}">${c[s]}${s[0].toUpperCase()}</span>`).join(" ") || '<span class="muted">none</span>'}</span></td>
        <td class="acts"><button class="btn btn-text" data-h="open">Open</button><button class="btn btn-text" data-h="export">Export</button><button class="btn btn-text" data-h="del" aria-label="Delete scan">Delete</button></td></tr>`;
    }).join("") : `<tr><td colspan="6" class="r-empty">No scans match.</td></tr>`;
  };
  main.querySelector("#hq").addEventListener("input", draw);
  main.querySelector("#hrows").addEventListener("click", e => {
    const b = e.target.closest("[data-h]"); if (!b) return;
    const h = history.find(x => x.id === b.closest("tr").dataset.id);
    if (b.dataset.h === "open") { current = h; location.hash = "#results"; }
    if (b.dataset.h === "export") openExport(h);
    if (b.dataset.h === "del" && confirm(`Delete the scan of ${h.target}? This can't be undone.`)) {
      history = history.filter(x => x !== h); saveHistory(); if (current === h) current = history[0]; draw(); toast("Scan deleted");
    }
  });
  draw();
}

/* ---------- Settings ---------- */
function viewSettings() {
  main.innerHTML = `<div class="view"><h1>Settings</h1><p class="sub">Defaults for new scans and where files are saved.</p>
    <form id="sform" class="settings">
      <div class="srow"><div><b>Default scan depth</b><p>Used when you start a new scan.</p></div>
        <div class="ctl"><div class="seg">${Object.entries(DEPTHS).map(([k, d]) => `<label><input type="radio" name="depth" value="${k}" ${settings.depth === k ? "checked" : ""}><b>${d.name}</b></label>`).join("")}</div></div></div>
      <div class="srow"><div><b>Default checks</b><p>Ticked by default on New Scan.</p></div>
        <div class="ctl cols">${Object.entries(MODULES).map(([k, v]) => `<label><input class="check" type="checkbox" name="modules" value="${k}" ${settings.modules.includes(k) ? "checked" : ""}>${v}</label>`).join("")}</div></div>
      <div class="srow"><div><b>Report folder</b><p>Where exported reports are saved.</p></div>
        <div class="ctl"><input class="input" name="folder" value="${esc(settings.folder)}" style="width:220px"></div></div>
      <div class="srow"><div><b>Request rate</b><p>Slow scans down so the target isn't overloaded.</p></div>
        <div class="ctl"><input class="input" type="number" name="rate" min="1" max="100" value="${settings.rate}" style="width:80px"><span class="mono text2">requests / second</span></div></div>
      <div class="srow"><div><b>Timeout</b><p>Skip a page that takes longer than this.</p></div>
        <div class="ctl"><input class="input" type="number" name="timeout" min="1" max="120" value="${settings.timeout}" style="width:80px"><span class="mono text2">seconds</span></div></div>
      <div class="srow"><div><b>Privacy</b><p>WebScanX never sends data anywhere. There is nothing to turn off.</p></div><div class="ctl"><span class="tag">Local only</span></div></div>
    </form>
    <div class="savebar"><button class="btn btn-text" id="reset">Reset to defaults</button><button class="btn btn-primary" id="save">Save changes</button></div></div>`;
  const f = main.querySelector("#sform");
  main.querySelector("#save").onclick = () => {
    if (!f.reportValidity()) return;
    Object.assign(settings, { depth: f.depth.value, modules: [...f.querySelectorAll("[name=modules]:checked")].map(i => i.value), folder: f.folder.value.trim() || "~/Documents", rate: +f.rate.value, timeout: +f.timeout.value });
    store.set("settings", settings); toast("Settings saved");
  };
  main.querySelector("#reset").onclick = () => { store.set("settings", {}); Object.assign(settings, { depth: "standard", modules: Object.keys(MODULES), folder: "~/Documents", rate: 10, timeout: 15 }); viewSettings(); toast("Defaults restored"); };
}

/* ---------- Export ---------- */
const dlg = document.getElementById("exportDlg"), exForm = document.getElementById("exportForm");
let exportScan = null;
function openExport(s) {
  exportScan = s;
  document.getElementById("exMeta").textContent = `${s.target.replace(/^https?:\/\//, "")} · ${s.ids.length} findings`;
  syncName(); dlg.showModal();
}
function syncName() {
  const d = new Date(exportScan.date).toISOString().slice(0, 10);
  exForm.fname.value = `webscanx-report-${d}.${exForm.fmt.value}`;
}
exForm.addEventListener("change", e => { if (e.target.name === "fmt") syncName(); });
exForm.addEventListener("submit", e => {
  if (e.submitter?.value !== "export") return;
  const o = { evidence: exForm.evidence.checked, ignored: exForm.ignored.checked, redact: exForm.redact.checked, fmt: exForm.fmt.value };
  const host = o.redact ? "https://[redacted]" : exportScan.target;
  const list = FINDINGS.filter(f => exportScan.ids.includes(f.id) && (o.ignored || f.status !== "ignored"));
  if (o.fmt === "pdf") { current = exportScan; location.hash = "#results"; setTimeout(() => print(), 300); return; }
  let body, type;
  if (o.fmt === "json") {
    body = JSON.stringify({ tool: "WebScanX 1.0", target: host, date: exportScan.date, duration: exportScan.duration, depth: exportScan.depth,
      findings: list.map(f => ({ severity: f.sev, title: f.title, location: f.loc, module: f.module, status: f.status, what: f.what, how_to_check: f.check, command: f.cmd, ...(o.evidence && { evidence: f.evidence }), fix: f.fix, references: f.refs })) }, null, 2);
    type = "application/json";
  } else {
    const md = [`# WebScanX report`, ``, `- Target: ${host}`, `- Date: ${fmtDate(exportScan.date)}`, `- Duration: ${exportScan.duration}`, `- Findings: ${list.length}`, ``,
      ...list.flatMap((f, i) => [`## ${i + 1}. [${f.sev.toUpperCase()}] ${f.title}`, ``, `Location: \`${f.loc}\` · Module: ${MODULES[f.module]} · Status: ${f.status}`, ``, `**What it is:** ${f.what}`, ``, `**How to check it yourself:**`, ...f.check.map((c, j) => `${j + 1}. ${c}`), "", "```", f.cmd, "```", ...(o.evidence ? [``, `**Evidence:**`, "```", f.evidence, "```"] : []), ``, `**How to fix it:**`, ...f.fix.map(x => `- ${x}`), ``, `References: ${f.refs}`, ``])].join("\n");
    if (o.fmt === "md") { body = md; type = "text/markdown"; }
    else {
      body = `<!doctype html><meta charset="utf-8"><title>WebScanX report</title><style>body{font:15px/1.6 system-ui;max-width:820px;margin:40px auto;padding:0 16px;background:#0D0C0C;color:#F2F0EF}pre,code{font-family:ui-monospace,monospace;background:#151414;border:1px solid #2A2828}pre{padding:10px;white-space:pre-wrap}h2{border-top:1px solid #2A2828;padding-top:20px}</style>`
        + md.split("\n").map(l => l.startsWith("## ") ? `<h2>${esc(l.slice(3))}</h2>` : l.startsWith("# ") ? `<h1>${esc(l.slice(2))}</h1>` : l === "```" ? " " : `<p>${esc(l)}</p>`).join("\n")
          .replace(/ \n([\s\S]*?)\n /g, (_, code) => `<pre>${code.replace(/<\/?p>/g, "")}</pre>`);
      type = "text/html";
    }
  }
  const a = Object.assign(document.createElement("a"), { href: URL.createObjectURL(new Blob([body], { type })), download: exForm.fname.value || "webscanx-report" });
  document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  toast(`Exported ${a.download}`);
});

route();
