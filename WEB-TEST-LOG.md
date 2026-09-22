# WebScanX — Web test log

Proof that the app runs **real scans**, not scripted output. One entry per web test.
Newest first. Append a new entry every time we scan a site; never rewrite old ones.

How an entry earns "REAL ✅": the finding must contain a fact that can only come from
the live target — a server banner, a reflected random marker, a real TLS/header state —
and we confirm it independently (a separate `curl`, or a marker that changes each run).

Stack when testing: demo target `python tools/demo_target.py` (:8000),
engine `python -m webscanx.server` (:8765), UI `cd site && pnpm run dev` (:5173).
Scan at `http://localhost:5173/#/dashboard/new-scan`.

---

## 2026-09-21 — scanme.nmap.org (real internet site) — REAL ✅

- **Target:** http://scanme.nmap.org/ (Nmap project's public host, scanning permitted by its owner)
- **Run by:** rider, in Chrome, through the full UI
- **Result:** 6 findings — 1 High, 1 Medium, 4 Low
- **Export:** `webscanx-975fc4495b5c.md` (rider's Downloads)
- **Findings:** HTTP no-TLS (High); missing CSP (Medium); missing X-Content-Type-Options,
  X-Frame-Options, Referrer-Policy, and server-version disclosure (Low).

**Independent proof it was real** — a separate `curl -sI http://scanme.nmap.org/`,
run outside the app, returned the exact same server banner the scan reported:

```
Server: Apache/2.4.7 (Ubuntu)
```

That version string can't be known without talking to the live server, and it was not
fed to the app. The 4 missing-header findings also matched the real response (those
headers are genuinely absent). Fewer findings than the demo because a real, fairly
clean site simply has less wrong with it — a scripted fake would show the same big list
every time. **Whole pipeline confirmed: real URL → real requests over the internet →
real responses → UI findings → correct exported report.**

---

## 2026-09-21 — local demo target (deliberately vulnerable fixture) — REAL ✅

- **Target:** http://127.0.0.1:8000/ (`tools/demo_target.py`, the test suite's vulnerable fixture)
- **Run by:** rider, in Chrome, through the full UI
- **Result:** 24 findings — 11 High, 8 Medium, 5 Low; all 15 modules ran
- **Top findings:** HTTP no-TLS, reflected XSS, SQL injection (error-based),
  permissive CORS, exposed `.env`.

**Independent proof it was real** — two XSS-only scans of the same target returned a
**different random marker each time**, echoed back from the target's own response:

```
scan 1  ...results for "><wsx9f87e0313c>...
scan 2  ...results for "><wsx8292f07745>...
```

A scripted result would repeat identical evidence; a live scan sends a fresh marker and
finds it reflected. This target is intentionally broken (planted XSS/SQLi/exposed files),
so the long list is expected — it proves the scanners fire, not that a real site is broken.

---

<!-- template — copy for the next test
## YYYY-MM-DD — <target> — REAL ✅ / FAILED ❌

- **Target:** <url>  (authorized because: <you own it / owner permits scanning>)
- **Run by:** <who, where>
- **Result:** <n> findings — <breakdown>
- **Export:** <filename if saved>

**Independent proof:** <curl banner match / changing random marker / other live fact>

```
<the matching evidence>
```
-->
